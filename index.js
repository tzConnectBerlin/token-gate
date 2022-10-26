export class TokenGate {
  constructor({ dbPool, dbSchema }) {
    this.db = dbPool;
    this.schema = dbSchema;

    this.rules = {};

    this.tokenIdNames = {};
    this.tokenNameIds = {};

    this.urlFromReqFunc = (req) => req.originalUrl; // or _parsedUrl.path ?
    this.tzAddrFromReqFunc = (req) => req.auth?.userAddress;
  }

  setUrlFromReqFunc(f) {
    this.tzAddrFromReqFunc = f;
  }

  setTzAddrFromReqFunc(f) {
    this.tzAddrFromReqFunc = f;
  }

  nameTokenId(id, name) {
    this.tokenIdNames[id] = name;
    this.tokenNameIds[name] = id;
    return this;
  }

  requireToken(endpoint, token) {
    if (isNaN(Number(token))) {
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

  middleware() {
    return (request, response, next) => {
      const url = this.urlFromReqFunc(request);
      const tzAddr = this.tzAddrFromReqFunc(request);
      this.hasAccess(url, tzAddr)
        .then((access) => {
          if (!access) {
            response.sendStatus(403);
            return;
          }
          next();
        })
        .catch((err) => {
          response.status(500).send(err);
        });
    };
  }

  async hasAccess(endpoint, tzAddr) {
    console.log(`checking ${tzAddr} access to ${endpoint}..`);
    let rule = this.rules[endpoint];
    if (typeof rule === "undefined") {
      return true;
    }

    return await this.ownsToken(rule.requiredToken, tzAddr);
  }

  async ownsToken(tokenId, tzAddr) {
    const amountOwned =
      (
        await this.db.query(
          `
SELECT
  idx_nat AS amount_owned
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
