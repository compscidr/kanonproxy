# kanonproxy
[![JVM Tests](https://github.com/compscidr/kanonproxy/actions/workflows/test.yml/badge.svg)](https://github.com/compscidr/kanonproxy/actions/workflows/test.yml)&nbsp;
[![codecov](https://codecov.io/gh/compscidr/kanonproxy/graph/badge.svg?token=yBstrWw9Mm)](https://codecov.io/gh/compscidr/kanonproxy)&nbsp;

An anonymous proxy written in kotlin. 

This project is meant to be a library that can run on android or linux. It does not provide
the client / server functionality. It is able to process packets which have been parsed
by https://github.com/compscidr/knet, manage sessions and make outgoing anonymous requests
based on the incoming traffic. It also receives the return traffic, and puts them into a
queue. 

It is up to consumers of the this library to implement a server or a tun/tap adapter, or a
VPN service on Android to make use of this library.