install:
	yarn install;

deploy local:
	forge script \
	script/Deploy.s.sol:DeployDev \
	--rpc-url http://127.0.0.1:8545 --broadcast -vvvv

deploy:
	forge script \
	--chain 84532 \
	script/Deploy.s.sol:DeployDev \
	--rpc-url $BASE_RPC_URL \
	--broadcast --verify -vvvv