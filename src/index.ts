import Pool from "pg-pool";
import { Client } from "pg";
import { Request, Response, NextFunction } from "express";
import yaml from "yaml";
import fs from "fs";
import { maybe } from "./utils.js";

type DbPool = Pool<Client>;
type Endpoint = string;

interface Rule<TokenType> {
  noRules?: boolean;
  allowedTokens?: TokenType[];
}

interface CustomizableColumns {
  address: string;
  token: string;
  amount: string;
}

export interface TokenGateSpec {
  [key: Endpoint]: Rule<number | string>;
}

export class TokenGate {
  db: DbPool;

  schema: string;
  table: string;
  columns: CustomizableColumns;

  tokenIdNames: { [key: number]: string };
  tokenNameIds: { [key: string]: number };

  rules: { [key: Endpoint]: Rule<number> };

  urlFromReq: (req: Request) => string;
  tzAddrFromReq: (req: Request) => string;

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

    this.tokenIdNames = {};
    this.tokenNameIds = {};

    this.urlFromReq = (req) => req.baseUrl;
    this.tzAddrFromReq = (req: any) => req.auth?.userAddress;
  }

  loadSpecFromFile(filepath: string, overwrite: boolean = true) {
    const parsed = yaml.parse(fs.readFileSync(filepath, "utf8"));
    if (parsed == null) {
      console.warn(`token gate: parse of ${filepath} is null, nothing loaded`);
      return;
    }

    if (overwrite) {
      this.rules = {};
      this.tokenIdNames = {};
      this.tokenNameIds = {};
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
      for (const id of Object.keys(tNames)) {
        const name = tNames[id];
        this.nameTokenId(Number(id), name);
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
  }

  setUrlFromReqFunc(f: (req: Request) => string) {
    this.tzAddrFromReq = f;
    return this;
  }

  setTzAddrFromReqFunc(f: (req: Request) => string): this {
    this.tzAddrFromReq = f;
    return this;
  }

  nameTokenId(id: number, n: string): this {
    this.tokenIdNames[id] = n;
    this.tokenNameIds[n] = id;
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

  allowToken(e: Endpoint, t: number | string): this {
    if (typeof t === "string") {
      if (typeof this.tokenNameIds[t] === "undefined") {
        throw new Error(`unknown token reference ${t}`);
      }
      t = this.tokenNameIds[t];
    }
    this.rules[e] = {
      allowedTokens: [...(this.rules[e]?.allowedTokens ?? []), t],
    };
    return this;
  }

  getSpec(): TokenGateSpec {
    return Object.keys(this.rules).reduce((res, endpoint) => {
      res[endpoint] = {
        noRules: this.rules[endpoint].noRules,
        allowedTokens: this.rules[endpoint].allowedTokens?.map(
          (t) => this.tokenIdNames[t] ?? t
        ),
      };
      return res;
    }, <TokenGateSpec>{});
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

  async hasAccess(endpoint: Endpoint, tzAddr: string): Promise<boolean> {
    const rule = this.getRuleForEndpoint(endpoint);
    if (typeof rule === "undefined" || rule.noRules) {
      return true;
    }

    if (typeof rule.allowedTokens !== "undefined") {
      console.log(`enforcing rule on ${endpoint}: ${JSON.stringify(rule)}`);
      return await this.ownsOneOf(tzAddr, rule.allowedTokens);
    }

    return true;
  }

  getRuleForEndpoint(endpoint: Endpoint): Rule<number> | undefined {
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

  async ownsOneOf(tzAddr: string, tokenIds: number[]): Promise<boolean> {
    const amountOwned =
      (
        await this.db.query(
          `
SELECT
  SUM(${this.columns.amount}) AS amount_owned
FROM "${this.schema}"."storage.ledger_live"
WHERE ${this.columns.address} = $1
  AND ${this.columns.token} = ANY($2)
      `,
          [tzAddr, tokenIds]
        )
      ).rows[0]?.amount_owned ?? 0;

    return amountOwned > 0;
  }
}
