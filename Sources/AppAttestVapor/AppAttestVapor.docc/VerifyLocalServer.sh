# Health route must stay public.
curl -i http://127.0.0.1:8080/health

# Challenge endpoint available without App Attest headers.
curl -i -X POST http://127.0.0.1:8080/app-attest/challenge \
  -H 'content-type: application/json' \
  -d '{"keyID":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}'

# Protected route must reject requests without valid headers.
curl -i http://127.0.0.1:8080/private
