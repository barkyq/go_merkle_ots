# go_merkle_ots
Command line utility for [opentimestamps](https://opentimestamps.org)

Deprecated in favour of [timestamp](https://github.com/barkyq/timestamp)

## usage 
Generate a root digest from the files in `<DIRECTORY>` and submit it to some number of calendar servers. Saves pending timestamp to `pending_XXX.ots`
```
go_merkle_ots -d <DIRECTORY> -c <CALENDAR_URL> -c <CALENDAR_URL> -c <CALENDAR_URL>
```

After enough time has passed, the calendar servers will each submit a BTC transaction committing to the submitted root hash, as explained in [this post](https://petertodd.org/2016/opentimestamps-announcement). Once at least one of these TXs has 6 confirmations, the pending timestamp can be upgraded by running:
```
go_merkle_ots -d <DIRECTORY> -u pending_XXX.ots
```
The attestations returned by the calendar servers are verified by `go_merkle_ots` using [a light btc client](https://blockstream.info). 

The files in the directory must not be changed, as otherwise the merkle root will be different from when it was submitted to the calendar servers.

Timestamp proofs for every file in `<DIRECTORY>` will be saved into a directory `proof_HEIGHT` where "height" is the lowest BTC block height committing to the root hash (depending on which calendar server submitted first). The proofs can be individually verified on, e.g., [opentimestamps.org](https://opentimestamps.org), or using one of the command line utilities for verifying opentimestamps, e.g., [ots-cli.js](https://github.com/opentimestamps/javascript-opentimestamps).

## target application
Generate timestamp proofs for all drafts of research papers (ideally with your name in the document somewhere), to prove their contents were known to you before some point in time.
