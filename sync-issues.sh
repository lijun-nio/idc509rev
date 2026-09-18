#!/bin/bash

mkdir -p github-issues

gh issue list \
  --repo lijun-nio/idc509rev \
  --limit 2000 \
  --state all \
  --json number,title,body,state,labels,createdAt,updatedAt \
  > github-issues/issues.json
