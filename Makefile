install:
	yarn install;

deploy:
	forge script \
	script/Deploy.s.sol:DeployDev \
	--rpc-url http://127.0.0.1:7545 --broadcast -vvvv