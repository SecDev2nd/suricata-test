#!/bin/bash

# 파일명
RULES_FILE="filter.rules"
FILE_PATH=$1

# Suricata 규칙 시작 번호
SID=10001

# Suricata 규칙 생성 함수
create_rule() {
  local site=$1
  local sid_http=$2
  local sid_https=$3

  echo "alert tcp any any -> any 80 (msg:\"Site $site Access\"; content:\"Host: $site\"; http_uri; nocase; sid:$sid_http; rev:1;)" >> $RULES_FILE
  echo "alert tcp any any -> any 443 (msg:\"Site $site HTTPS Access\"; tls_sni; content:\"$site\"; nocase; sid:$sid_https; rev:1;)\n" >> $RULES_FILE
  
}

# 룰 파일 존재하면 삭제
if [ -f "$RULES_FILE" ]; then
    rm $RULES_FILE
fi

# 파일이 존재하는지 확인
if [ -f "$FILE_PATH" ]; then
    # 파일을 한 줄씩 읽어오기
    while IFS= read -r line; do
        site=$line
        sid_http=$SID
        sid_https=$((SID + 1))
        create_rule $site $sid_http $sid_https
        SID=$((SID + 2))
    done < "$FILE_PATH"
else
    echo "파일을 찾을 수 없습니다: $FILE_PATH"
fi

echo "done"
