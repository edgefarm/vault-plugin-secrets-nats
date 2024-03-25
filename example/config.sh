#!/bin/bash
set -e
BGREEN='\033[1;32m'
NC='\033[0m' # No Color

echo -e "${BGREEN}> Creating NATS resources (operator and sysaccount)${NC}"    
vault write nats-secrets/issue/operator/myop/account/sys/user/default-push @sysaccount/default-push.json
vault write nats-secrets/issue/operator/myop/account/sys @sysaccount/sysaccount.json
vault write nats-secrets/issue/operator/myop @operator/operator.json

echo -e "${BGREEN}> Generate NATS server config with preloaded operator and sys account settings${NC}"    
OPERATOR_JWT=$(vault read -format=json nats-secrets/jwt/operator/myop  | jq -r .data.jwt)
SYSACCOUNT_PUBLICKEY=$(vault read -format=json nats-secrets/nkey/operator/myop/account/sys  | jq -r .data.publicKey)
SYSACCOUNT_JWT=$(vault read -format=json nats-secrets/jwt/operator/myop/account/sys  | jq -r .data.jwt)

TEMPLATE="operator: $OPERATOR_JWT\n
system_account: $SYSACCOUNT_PUBLICKEY\n
resolver {\n
\ttype: full\n
\tdir: '/tmp/jwt'\n
\tallow_delete: true\n
\tinterval: \"2m\"\n
\ttimeout: \"1.9s\"\n
}\n
resolver_preload: {\n
\t$SYSACCOUNT_PUBLICKEY: $SYSACCOUNT_JWT\n
}\n"
echo -e ${TEMPLATE} > resolver.conf

echo -e "${BGREEN}> Starting up NATS server${NC}"    
docker network create nats
docker run -d --rm -it --name nats --network nats -p 4222:4222 -v $(pwd)/resolver.conf:/config/resolver.conf nats:2.9.14-alpine3.17 -c /config/resolver.conf -DV
sleep 1
echo -e "${BGREEN}> Creating normal account and user${NC}"    
vault write nats-secrets/issue/operator/myop/account/myaccount @account/myaccount.json
vault write nats-secrets/issue/operator/myop/account/myaccount/user/user @account/myuser.json
echo -e "${BGREEN}> Exporting user creds file${NC}"    
vault read -field creds nats-secrets/creds/operator/myop/account/myaccount/user/user > creds
echo -e "${BGREEN}> Publishing using user creds file${NC}"    
docker run --rm -it --name nats-box --network nats -v $(pwd)/creds:/creds natsio/nats-box:0.13.4 nats pub -s nats://nats:4222 --creds /creds foo bar
echo -e "${BGREEN}> Cleaning up...${NC}"    
docker kill nats
docker network rm nats
echo -e "${BGREEN}> done.${NC}"    
