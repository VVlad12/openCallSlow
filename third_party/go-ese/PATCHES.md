# Local patches

Copy of www.velocidex.com/golang/go-ese v0.2.0 (Apache-2.0, see LICENSE),
used through a `replace` directive in the root go.mod.

- parser/catalog.go `ParseTaggedValues`: skip tags whose offsets are out of
  order or out of range instead of panicking. Live SRUM databases copied with
  `esentutl /vss` contain such records.
