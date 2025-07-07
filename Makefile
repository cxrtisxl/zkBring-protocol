install:
	yarn install;

# Test commands
test:
	forge test --summary

test-all:
	forge test --via-ir --ffi --summary

test-registry:
	forge test --match-path "test/BringRegistry.t.sol" --ffi -v

test-factory:
	forge test --match-path "test/BringDropFactory.t.sol" -v

test-base:
	forge test --match-path "test/BringDropBase.t.sol" -v

test-verification:
	forge test --match-path "test/BringDropByVerification.t.sol" --ffi -v

test-zkbring:
	forge test --match-path "test/zkBring.t.sol" --ffi -v

# Deploy commands
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