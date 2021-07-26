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
