# Socket

Socket - клиентская обёртка сокетов (TCP) для Windows. Написано на C с использованием MSVS 2019, WinAPI и Winsock2 (2.2). Для обеспечения поддержки TLS используется библиотека OpenSSL 1.1.1m (от 14 Дек 2021). В папке Libs\openssl\ находится статически собранная версия.

Репозиторий содержит:
- решение MSVS 2019 (Socket.sln);
- исходники (Socket\);
- пример (Example\);
- тесты (Tests\);
- скрипты для очистки (clean.bat удаляет увесистую папку ipch в .vs\Socket\v16\ и бинарники, clean_all.bat удаляет то же + всю папку .vs);
- используемые библиотеки (Libs\);
- сертификаты, ключи и скрипты для тестирования (Misc\).

Папка Misc:
- certs\ - распакованные и хешированные сертификаты из комплекта корневых сертификатов в формате OpenSSL
- client\ - сертификаты и ключи для клиентской стороны
- server\ - сертификаты и ключи для серверной стороны
- c_rehash.pl - скрипт от OpenSSL для хеширования имён файлов
- cacert.pem - комплект корневых сертификатов ЦС от Mozilla
- certsextractor.py - скрипт для распаковки сертификатов из комплекта корневых сертификатов (пути указываются внутри)

Решение состоит из двух проектов (Example и Tests) с динамической/статической конфигурациями для x86 и x64. Протестировано на Windows Vista и выше.

OpenSSL 1.1.1 можно скачать и собрать автоматически с использованием Vcpkg (https://github.com/microsoft/vcpkg). С OpenSSL версии 3.0 ещё не проверено, но, вероятно, будет работать.
____
Socket is a client-side socket (TCP) wrapper for Windows. Written in C using MSVS 2019, WinAPI and Winsock2 (2.2). OpenSSL 1.1.1m (from 14 Dec 2021) is used for TLS support. In folder Libs\openssl\ resides a statically built version.

The repository contains:
- MSVS 2019 solution (Socket.sln);
- source code (Socket\);
- example (Example\);
- tests (Tests\);
- scripts for clean up (clean.bat removes the weighty ipch folder in .vs\Socket\v16\ and also removes binaries, clean_all.bat removes the same as the previous one plus the entire .vs folder);
- libraries used (Libs\);
- certificates, keys and scripts for testing (Misc\).

The Misc folder:
- certs\ - extracted and hashed certificates from the certificates bundle in OpenSSL format
- client\ - certificates and keys for the client side
- server\ - certificates and keys for the server side
- c_rehash.pl - script from OpenSSL for hashing filenames
- cacert.pem - a bundle of CA root certificates from Mozilla
- certsextractor.py - script for extracting certificates from the bundle (paths are specified inside)

The solution consists of two projects (Example and Tests) with dynamic/static configurations for both x86 and x64 architectures. Tested on Windows Vista and above.

You can get OpenSSL 1.1.1 using Vcpkg (https://github.com/microsoft/vcpkg). With OpenSSL 3.0 hasn't been tested yet, but will probably work.

## Building

Microsoft Visual Studio 2019 is used to build the solution.

Once built, you can find the binaries in the Bins\ folder:

- x64\
  - Debug\
  - Debug (static)\
  - Release\
  - Release (static)\
- x86\
	- Debug\
	- Debug (static)\
	- Release\
	- Release (static)\

## Authors

```
blightn <blightan@gmail.com>
```
## License

This project is licensed under the MIT License. See LICENSE in the project's root directory.
