#!/usr/bin/env bash

source main.sh

authenticateOci
UserModifyRequest17sp4 "7025551234@domain.com" "John" "Smith"
UserModifyRequest17sp4 "3035559876@domain.com" "Alice" "Jones"
