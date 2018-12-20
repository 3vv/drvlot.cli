# ethCli

ethCli - DrvLot Command Line Interface

Cmds:
  - `api             `  Set API and console options
  - `acc             `  Set default account
  - `FTO, fto        `  Set FTO account
  - `accounts, accs  `  List all accounts
  - `MISC, misc      `  List miscellaneous items
  - `big             `  Encode bigint as a hex string with 0x prefix, or decode it as a quantity
  - `hex             `  Return hexadecimal (0x...) of the given string, or decode the given data
  - `sha             `  Return Keccak-256 (not the standardized SHA3-256) of the given data
  - `sign            `  Signature with sign(keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)))
  - `code            `  Return code at a given address & block
  - `storage         `  Return the value from a storage position at a given address + index in block
  - `balance, bal    `  Get balance
  - `block, blk      `  Get somethings in a block
  - `transaction, txn`  Get/put somethings for a transaction
  - `event, evt      `  New/polling/uninstall a filter object
  - `help, h         `  Shows a list of commands or help for one command

Opts:
  - `-e value     ` encode the given data
  - `-d value     ` decode the given data
  - `--help, -h   ` show help
  - `--version, -v` print the version

### Download and Install

#### Use Binary Distributions

1.Install docker on your operating system

2.Execute command
  - `docker pull dlot/ethlot_cli:latest`

3.Locate your ethereum rpc server `<such as http://127.0.0.1:8545>`

4.Organize your commands & options to replace the following "$@"

5.Execute command
  - `docker run --rm dlot/ethlot_cli:latest /app/ethlot/cli "$@"`

6.(Optional) Save the above script as an executable file `ethCli`
  - `./ethCli $CMDs $OPTs`

#### Install From Source

1.Select your working directory (as environment variable D)

2.Execute command
  - `git clone $GIT_HOST/$USR_NAME/drvlot.cli.git "$D/drvlot.cli"`
  - `cd "$D/drvlot.cli" && ./bcp.sh`

3.Follow your Go knowledge & your wants...

### Advanced usage

Follow your hands.

Go to think & use bravely.

### Contributing

To contribute, please pull requests of your contributing code to above.

## Fly freely!