import Pool from "pg-pool";
import { Client } from "pg";
import { Request, Response, NextFunction } from "express";
import yaml from "yaml";
import fs from "fs";
import { maybe } from "./utils.js";

type DbPool = Pool<Client>;
type Endpoint = string;

interface Rule {
  noRules?: boolean;
  allowedTokens?: string[];
}

interface CustomizableColumns {
  address: string;
  token: string;
  amount: string;
}

export interface TokenGateSpec {
  [key: Endpoint]: Rule;
}

interface Range {
  from: number;
  to: number;
}

export class TokenGate {
  db: DbPool;

  schema: string;
  table: string;
  columns: CustomizableColumns;

  tokenNameRanges: { [key: string]: Range };

  rules: { [key: Endpoint]: Rule };

  urlFromReq: (req: Request) => string;
  tzAddrFromReq: (req: Request) => string | undefined;

  applyAddressWhitelist: boolean;

  constructor({ dbPool }: { dbPool: DbPool }) {
    this.db = dbPool;

    this.schema = "token_gate";
    this.table = "storage.ledger_live";
    this.columns = {
      address: "idx_address",
      token: "idx_nat",
      amount: "nat",
    };

    this.rules = {};

    this.tokenNameRanges = {};

    this.urlFromReq = (req) => req.baseUrl;
    this.tzAddrFromReq = (req: any) => req.auth?.userAddress;

    this.applyAddressWhitelist = false;
  }

  loadSpecFromFile(filepath: string, overwrite: boolean = true): this {
    const parsed = yaml.parse(fs.readFileSync(filepath, "utf8"));
    if (parsed == null) {
      console.warn(`token gate: parse of ${filepath} is null, nothing loaded`);
      return this;
    }

    if (overwrite) {
      this.rules = {};
      this.tokenNameRanges = {};
    }

    maybe(parsed.schema, (s) => this.setSchema(s));
    maybe(parsed.table, (t) => this.setTable(t));
    maybe(parsed.columns, (c) => {
      this.setColumns({
        address: c.address ?? this.columns.address,
        token: c.token ?? this.columns.token,
        amount: c.amount ?? this.columns.amount,
      });
    });

    maybe(parsed.tokenNames, (tNames) => {
      for (const name of Object.keys(tNames)) {
        let range = tNames[name];
        if (typeof range === "number") {
          range = {
            from: range,
            to: range,
          };
        }
        if (
          typeof range.from === "undefined" ||
          typeof range.to === "undefined"
        ) {
          throw `invalid named token id range, must be either a number or a 'from: ..' and a 'to: ...'`;
        }
        this.nameTokenIdRange(name, range);
      }
    });

    maybe(parsed.rules, (r) => {
      for (const endpoint of Object.keys(r)) {
        const endpointRule = r[endpoint];
        if (endpointRule === "no_rules") {
          this.rules[endpoint] = {
            noRules: true,
          };
          continue;
        }
        for (const token of r[endpoint].one_of ?? []) {
          this.allowToken(endpoint, token);
        }
      }
    });

    return this;
  }

  setUrlFromReqFunc(f: (req: Request) => string) {
    this.tzAddrFromReq = f;
    return this;
  }

  setTzAddrFromReqFunc(f: (req: Request) => string | undefined): this {
    this.tzAddrFromReq = f;
    return this;
  }

  nameTokenIdRange(n: string, r: Range): this {
    if (r.from > r.to) {
      throw `range is not allowed to have a from bigger than a to (range sspecified is ${JSON.stringify(
        r
      )}`;
    }
    for (const existingName of Object.keys(this.tokenNameRanges)) {
      const existingRange = this.tokenNameRanges[existingName];
      if (r.from <= existingRange.to && existingRange.from <= r.to) {
        throw `not allowed to have overlapping ranges. range ${JSON.stringify(
          r
        )} overlaps with previously specified range ${JSON.stringify(
          existingRange
        )}`;
      }
    }
    this.tokenNameRanges[n] = r;
    return this;
  }

  setSchema(s: string): this {
    this.schema = s;
    return this;
  }

  setTable(t: string): this {
    this.table = t;
    return this;
  }

  setColumns(c: CustomizableColumns): this {
    this.columns = c;
    return this;
  }

  allowToken(e: Endpoint, t: string): this {
    this.rules[e] = {
      allowedTokens: [...(this.rules[e]?.allowedTokens ?? []), t],
    };
    return this;
  }

  enableAddressWhitelist(): this {
    this.applyAddressWhitelist = true;
    return this;
  }

  getSpec(): TokenGateSpec {
    return Object.keys(this.rules).reduce((res, endpoint) => {
      res[endpoint] = {
        noRules: this.rules[endpoint].noRules,
        allowedTokens: this.rules[endpoint].allowedTokens,
      };
      return res;
    }, <TokenGateSpec>{});
  }

  getEndpointAllowedTokens(e: string): string[] | undefined {
    return this.#getRuleForEndpoint(e)?.allowedTokens;
  }

  middleware(): (req: Request, resp: Response, next: NextFunction) => void {
    return (req: Request, resp: Response, next: NextFunction) =>
      this.use(req, resp, next);
  }

  use(req: Request, resp: Response, next: NextFunction): void {
    const url = this.urlFromReq(req);
    const tzAddr = this.tzAddrFromReq(req);

    this.hasAccess(url, tzAddr)
      .then((access) => {
        if (!access) {
          resp.sendStatus(403);
          return;
        }
        next();
      })
      .catch((err) => {
        console.log(err);
        resp.sendStatus(500);
      });
  }

  async isAddressInWhitelist(userAddress?: string): Promise<boolean> {
    if (typeof userAddress === "undefined") {
      return false;
    }
    const qryResp = await this.db.query(
      `
SELECT 1
FROM whitelisted_wallet_addresses
WHERE address = $1
  AND NOT claimed
      `,
      [userAddress]
    );
    if (qryResp.rowCount === 0) {
      return false;
    }
    return true;
  }

  async hasAccess(
    endpoint: Endpoint,
    tzAddr: string | undefined
  ): Promise<boolean> {
    const rule = this.#getRuleForEndpoint(endpoint);
    if (typeof rule === "undefined" || rule.noRules) {
      return true;
    }

    if (typeof rule.allowedTokens !== "undefined") {
      if (typeof tzAddr === "undefined") {
        return false;
      }
      if (
        this.applyAddressWhitelist &&
        !(await this.isAddressInWhitelist(tzAddr))
      ) {
        return false;
      }
      return await this.#ownsOneOf(tzAddr, rule.allowedTokens);
    }

    return true;
  }

  async getOwnedTokens(tzAddr: string): Promise<string[]> {
    return (await this.#getOwnedTokens(tzAddr)).flatMap(
      (t) => this.#tryNameTokenId(t) ?? []
    );
  }

  #tryNameTokenId(tokenId: number): string | undefined {
    for (const n of Object.keys(this.tokenNameRanges)) {
      const r = this.tokenNameRanges[n];
      if (tokenId >= r.from && tokenId <= r.to) {
        return n;
      }
    }
  }

  #getRuleForEndpoint(endpoint: Endpoint): Rule | undefined {
    const stripTrailingSlash = (x: Endpoint) => x.replace(/\/+$/, "");
    const reduceEndpoint = (x: Endpoint) =>
      stripTrailingSlash(x).split("/").slice(0, -1).join("/") + "/";

    for (
      endpoint = stripTrailingSlash(endpoint);
      endpoint !== "/";
      endpoint = reduceEndpoint(endpoint)
    ) {
      const rule = this.rules[endpoint];
      if (typeof rule !== "undefined") {
        return rule;
      }
    }

    return this.rules["/"];
  }

  async #ownsOneOf(tzAddr: string, tokenRanges: string[]): Promise<boolean> {
    const ownedTokens = await this.#getOwnedTokens(tzAddr);
    const rangesAllowed = tokenRanges.map((n) => this.tokenNameRanges[n]);
    return ownedTokens.some((t) =>
      rangesAllowed.some((r) => t >= r.from && t <= r.to)
    );
  }

  async #getOwnedTokens(tzAddr: string): Promise<number[]> {
    return (
      await this.db.query(
        `
SELECT
  "${this.columns.token}" AS token_id
FROM "${this.schema}"."${this.table}"
WHERE "${this.columns.address}" = $1
  AND "${this.columns.amount}" > 0
      `,
        [tzAddr]
      )
    ).rows.map((row: any) => Number(row["token_id"]));
  }
}
