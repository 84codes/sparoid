## [1.1.13] - 2024-09-25

- Lookup by http instead of dns
- Build for ubuntu 24, debain 12 and 14

## [1.1.12] - 2023-03-01

- Systemd: Dont set MemoryHigh for the Sparoid service

## [1.1.11] - 2023-01-31

- Client improvement: If hostname resolves to multiple IPs fdpass will connect to them in parallel and exit when the first succeeds
- Client improvement: Sparoid::Client.new can parse INI files
- Client improvement: Block/wait for UDP packets to be sent

## [1.1.10] - 2022-09-15

- Bundle static libnftables in debian binaries, doesn't seem to leak memory and works also in ubuntu 18.04

## [1.1.9] - 2022-09-14

- Revert to one nft at a time becasue some versions of nft -i also leaks memory

## [1.1.8] - 2022-09-14

- Because libnftable seems to leak memory in some versions use nft -i

## [1.1.7] - 2022-09-14

- Save a few allocations

## [1.1.6] - 2022-09-14

- Create/free a nftables context for each request

## [1.1.5] - 2022-09-13

- Increase MemoryMax to 32M

## [1.1.4] - 2022-09-13

- Increase MemoryMax to 12M

## [1.1.3] - 2022-09-12

- Decrease number of allocations when processing packets
- SystemD service limits memory to 5MB
- Allow unknown keys in config file for client so that the same config can be used for server and client

## [1.1.2] - 2022-08-15

- build option -Dwithout_nftables, that fallsback to nft binary for nftables-cmd (for ubuntu 18.04)

## [1.1.1] - 2022-08-15

- bug fix: restore open/close-cmd support

## [1.1.0] - 2022-08-15

- Direct nftables support
- Show version with `sparoid --version`

## [1.0.13] - 2022-05-31

- Cache the public IP to disk for 60s in the client

## [1.0.12] - 2022-05-03

- Correct dependencies in deb package

## [1.0.11] - 2022-05-02

- Don't check if source IP and IP and packet matches, use IP in packet

## [1.0.10] - 2021-09-21

- No default open/close commands
- Dont print keys on startup

## [1.0.9] - 2021-09-13

- Support for multiple encryption and HMAC keys in the server, for key rotation

## [1.0.8] - 2021-08-23

- Client resolvs IPs before generating the message (so that the message isn't stale before sending in the case resolving took a long time)

## [1.0.7] - 2021-07-26

- Can create an instance of Client that caches IP

## [1.0.6] - 2021-07-26

- Client send packets to all resolved IPs for a hostname

## [1.0.5] - 2021-06-14

- Fix ARM deb package, compiling the correct files
- SystemD service always restart no, not only on failure

## [1.0.4] - 2021-06-11

- Move src files up one level
- Don't allow specifying key/hmac on cmd line for client cli

## [1.0.3] - 2021-06-11

- Put all classes in the Sparoid namespace/module

## [1.0.2] - 2021-05-07

- Building deb packages for ARM and x86_64 are now working again

## [1.0.1] - 2021-04-13

- SSH ProxyCommand support, sparoid connect, which send SPA, TCP connect and pass the FD to parent
- Static IP for OpenDNS resolver, requires one less lookup
- Drop packets early if packet length doesn't match
- Build with 1.0.0

## [1.0.0] - 2021-03-11

- Initial release
