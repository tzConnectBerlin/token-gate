import Pool from "pg-pool";
import { Client } from "pg";
import { Request, Response, NextFunction } from "express";

type DbPool = Pool<Client>;
type Endpoint = string;

interface Rule<TokenType> {
  requireToken: TokenType;
}

export interface TokenGateSpec {
  [key: Endpoint]: Rule<number | string>;
}

export class TokenGate {
  db: DbPool;
  schema: string;

  tokenIdNames: { [key: number]: string };
  tokenNameIds: { [key: string]: number };

  rules: { [key: Endpoint]: Rule<number> };

  urlFromReq: (req: Request) => string;
  tzAddrFromReq: (req: Request) => string;

  constructor({ dbPool, dbSchema }: { dbPool: DbPool; dbSchema: string }) {
    this.db = dbPool;
    this.schema = dbSchema;

    this.rules = {};

    this.tokenIdNames = {};
    this.tokenNameIds = {};

    this.urlFromReq = (req) => req.baseUrl; // or _parsedUrl.path ?
    this.tzAddrFromReq = (req: any) => req.auth?.userAddress;
  }

  setUrlFromReqFunc(f: (req: Request) => string) {
    this.tzAddrFromReq = f;
  }

  setTzAddrFromReqFunc(f: (req: Request) => string) {
    this.tzAddrFromReq = f;
  }

  nameTokenId(id: number, name: string) {
    this.tokenIdNames[id] = name;
    this.tokenNameIds[name] = id;
    return this;
  }

  requireToken(endpoint: Endpoint, token: number | string) {
    if (typeof token === "string") {
      if (typeof this.tokenNameIds[token] === "undefined") {
        throw new Error(`unknown token reference ${token}`);
      }
      token = this.tokenNameIds[token];
    }
    this.rules[endpoint] = {
      requireToken: token,
    };
    return this;
  }

  getSpec(): TokenGateSpec {
    return Object.keys(this.rules).reduce((res, endpoint) => {
      const requireTokenId = this.rules[endpoint].requireToken;
      const requireTokenName = this.tokenIdNames[requireTokenId];
      res[endpoint] = {
        requireToken: requireTokenName ?? requireTokenId,
      };
      return res;
    }, <TokenGateSpec>{});
  }

  middleware(): (req: Request, resp: Response, next: NextFunction) => void {
    return (req: Request, resp: Response, next: NextFunction) =>
      this.use(req, resp, next);
  }

  use(req: Request, resp: Response, next: NextFunction): void {
    console.log(req);
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
    if (typeof rule === "undefined") {
      return true;
    }

    console.log(`enforcing rule on ${endpoint}: ${JSON.stringify(rule)}`);
    return await this.ownsToken(rule.requireToken, tzAddr);
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

  async ownsToken(tokenId: number, tzAddr: string): Promise<boolean> {
    const amountOwned =
      (
        await this.db.query(
          `
SELECT
  nat AS amount_owned
FROM "${this.schema}"."storage.ledger_live"
WHERE idx_nat = $1
  AND idx_address = $2
      `,
          [tokenId, tzAddr]
        )
      ).rows[0]?.amount_owned ?? 0;

    return amountOwned > 0;
  }
}
