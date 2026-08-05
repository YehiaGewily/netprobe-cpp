# GeoLite2 databases

To enable GeoIP and ASN enrichment, download these free GeoLite2 databases from a MaxMind account and place them in this directory:

- `GeoLite2-Country.mmdb`
- `GeoLite2-ASN.mmdb`

The databases are intentionally not committed here: MaxMind's download service requires your own account and license key. NetProbe starts normally without them, and the Flows table shows `-` until the files are present.
