## 보안SW구현 SPN구(조)



\- 20242081 박예나 (팀장)

\- 20242067 김도윤

\- 20242100 장하영

\- 20242102 정석원



---



본 애플리케이션은 대용량 파일(약 1GB)까지 처리 가능한 콘솔 기반 파일 보안 프로그램

으로, 내부적으로 SWTeam9 Crypto Library를 호출하여 암호화 및 무결성 검증 기능을 제

공한다. 



---



\## 구현 기능



\- AES 기반 파일 암호화 / 복호화

&nbsp; - AES-128 / AES-192 / AES-256 지원

&nbsp; - CBC / CTR 모드 지원

\- HMAC-SHA512 기반 무결성 생성 및 검증

\- Encrypt-then-MAC 방식 지원

\- AES Reference / T-table 구현 선택 가능

\- 키 파일 기반 암호화

\- 콘솔 진행률(%) 출력

\- Linux / macOS / Windows(WSL) 환경 지원



---



\## 프로젝트 구조



team9/

├── app/

│   └── app.c              # 애플리케이션 main

├── src/

│   ├── AES\_REF.c

│   ├── AES\_TABLE.c

│   ├── T-table.c

│   ├── crypto\_api.c

│   ├── hmac.c

│   ├── sha512.c

│   ├── modes.c

│   ├── utils.c

│   └── error.c

├── include/

│   ├── crypto\_api.h

│   ├── aes.h

│   └── error.h

├── test/

│   └── test.c             # 테스트용 프로그램

├── Makefile

└── README.md



---



\##빌드 환경

Language: C (C99)

Compiler: gcc or clang

Build Tool: make



---



\##빌드 방법

▶ Linux / macOS

1. git clone https://github.com/SWTEAM99/team9.git

2\.	cd team9

3\. make app (또는 test 파일 실행을 원한다면 make test) 

4\. ./crypto\_app (또는 ./crypto\_test) 



▶ Windows (WSL)

Windows 기본 PowerShell에서는 make를 사용할 수 없으므로

WSL(Windows Subsystem for Linux) 환경에서 빌드한다.

1\.	WSL 설치 여부 확인 

PowerShell 또는 Windows Terminal에서 다음 명령을 실행한다. 

`wsl –status` 

• WSL 관련 정보가 출력되면 이미 설치된 상태이다. 

• 명령어가 인식되지 않거나 오류가 발생하면 WSL이 설치되지 않은 상태이다. 

2\.	WSL 설치 (미설치 시) 

WSL이 설치되어 있지 않은 경우, 다음 명령을 실행한다. 

`wsl –install` 

설치 과정 중 재부팅 안내가 나오면 시스템을 재부팅한다. 

3\.	WSL(리눅스 환경) 실행 

PowerShell에서 다음 명령을 실행하여 WSL로 진입한다. 

`wsl`  

4\. 빌드 도구 설치 

WSL 터미널에서 다음 명령을 실행하여 make 및 GCC 컴파일러를 설치한다. 

`sudo apt update` 

`sudo apt install -y build-essential`

설치 완료 후 다음 명령으로 정상 설치 여부를 확인한다. 

`make --version` 

`gcc –version` 

버전 정보가 출력되면 정상적으로 설치된 것이다.



이후 macOS와 Linux 환경과 동일한 방식으로 진행하면 된다.  



▶ Windows (비주얼스튜디오)

1. GitHub 저장소에서 소스 코드를 ZIP 파일로 다운로드하거나 git clone으로 내려

받는다. 다음 파일들을 모두 프로젝트에 포함시킨다. 

\-app.c, test.c 

-crypto\_api.h, crypto\_api.c 

\-내부 암호 라이브러리 소스 파일(.c, .h) 

2\.	Visual Studio에서 콘솔 애플리케이션 프로젝트 생성 

3\.	소스 파일 추가 

4\.	빌드 후 실행 



---



\##메인 메뉴 구성

1\. Encrypt

2\. Decrypt

3\. Generate HMAC

4\. Verify HMAC

5\. Generate Key

0\. Exit



---



\##암호화 방식

\-입력 파일 경로 입력



\-출력 파일 경로 입력



\-AES 키 입력 (파일 또는 직접 입력)



\-AES 키 길이 선택 (128 / 192 / 256)



\-암호화 모드 선택 (CBC / CTR)



\-구현 방식 선택 (Reference / T-table)



\-HMAC 사용 여부 선택



\-salt 및 tag 길이 설정 가능 (1~64B)



\-CBC 모드의 IV, CTR 모드의 Nonce는 암호문 파일 앞부분에 자동 저장된다.



---



\##복호화 방식

\-암호화 시 사용한 동일한 키 / 모드 / 옵션 필요



\-암호문 파일 앞부분에서 IV/Nonce 자동 추출



\-HMAC 적용 시:



\-복호화 전 HMAC 검증



\-검증 실패 시 복호화 중단



---



\##HMAC 생성/검증

\-키 입력 방식



\-0x로 시작 → 16진수 키



\-그 외 → 문자열 키



\-salt 입력 가능



\-태그 길이: 1~64 바이트



---



\##키 생성

\-AES Key

길이: 16 / 24 / 32 바이트



\-난수 기반 생성 후 파일 저장



\-HMAC Key

비트 단위 키 길이 입력 (기본 256, 최대 512) 후 파일 저장



---



\##주의사항

\-암·복호화 시 키, 모드(CBC/CTR), 옵션이 동일해야 한다.



\-HMAC 사용 시 키, salt, 태그 길이가 동일해야 검증 가능하다.



\-암호문 파일 앞부분(IV/Nonce 영역)을 수정하면 복호화할 수 없다.



\-입력 파일과 출력 파일 경로를 동일하게 설정하면 원본이 손상될 수 있다.



\-Hash/HMAC은 기밀성이 아닌 무결성 검증 목적이다.





