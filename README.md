URL-Analyzer



피싱 URL 탐지 및 위험도 분석 웹 애플리케이션



1\. 프로젝트 소개



URL-Analyzer는 사용자가 입력한 URL의 악성 여부를 분석하고 위험도를 확인할 수 있는 Python 기반 웹 애플리케이션입니다.



공개 CTI 데이터와 정상 후보 URL 데이터를 활용하여 URL을 분석하고, 단일 URL 분석부터 CSV 일괄 분석, 분석 기록 및 통계 확인까지 지원합니다.



2\. 주요 기능



\- URL 단일 분석: URL 정규화 및 악성 URL 데이터베이스 대조

\- 위험도 분석: URL 구조적 특징을 기반으로 위험 점수 계산

\- CSV 일괄 분석: 여러 URL을 한 번에 분석하고 결과 확인

\- 분석 기록: 분석 결과를 SQLite 데이터베이스에 저장

\- 통계 대시보드: 분석 결과와 위험 점수 분포 시각화



3\. 데이터 구성



총 220,991건의 URL 데이터를 활용합니다.



| 데이터 출처 | 데이터 수 | 구분 

| KISA | 17,832건 | 악성 |

| PhishTank | 43,789건 | 악성 |

| URLhaus | 60,826건 | 악성 |

| URL-Phish | 98,544건 | 정상 후보 |

| 합계 | 220,991건 | |



4\. 개발 환경



\- Python

\- Streamlit

\- Pandas

\- SQLite

\- Pytest

\- GitHub Actions



5\. 프로젝트 실행 방법



① 저장소 복제



```bash

git clone https://github.com/hayeonrhdwn-debug/URL-Analyzer.git

cd URL-Analyzer

```



② 필요한 라이브러리 설치



```bash

pip install -r requirements.txt

```



③ 웹 애플리케이션 실행



```bash

streamlit run app.py

```



브라우저에서 표시되는 주소로 접속합니다.



6\. 테스트 실행



```bash

python -m pytest tests -v

```



GitHub Actions를 통해 코드 변경 시 자동 테스트를 수행합니다.



7\. 팀원별 역할



담당: 역할 

김하연: URL 분석 로직, 데이터 관리 및 전체 통합 

김수혁: Streamlit 웹 화면 개선 

손원진: CSV 일괄 분석 기능 개선 

장연우: 분석 기록 및 통계 대시보드 개선 



8\. 프로젝트 저장소



GitHub: https://github.com/hayeonrhdwn-debug/URL-Analyzer



9\. 분석 시 유의사항



본 프로그램의 위험 점수는 URL의 구조적 특징을 기반으로 계산하는 휴리스틱 점수이며, 악성 여부의 확률을 의미하지 않습니다.



데이터베이스에 등록되지 않은 URL이 안전하다는 의미도 아닙니다.

