UPDATE app_attest_credentials
SET counter = $2
WHERE key_id = $1
  AND counter < $2
RETURNING counter;
