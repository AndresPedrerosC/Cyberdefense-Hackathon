# Cyberdefense-Hackathon

## TODO: Senso API key needed

The Senso.ai integration (`app/integrations/senso.py`) is built but has not run against a real
account yet. Until a key is set, ingest is skipped and the "Ask the knowledgebase" box on the
Target tab says Senso is not configured.

1. Get an org API key from Senso (https://docs.senso.ai/docs/api-keys).
2. Set `SENSO_API_KEY` in your local `.env` (never commit it). `SENSO_BASE_URL` is optional and
   defaults to `https://apiv2.senso.ai/api/v1`.
3. Restart the server and run a public-domain scan. The Activity feed should show
   "Ingested into Senso", then the ask box becomes usable once Senso finishes indexing.

Each ingest and search spends Senso credits. An out-of-credits org returns HTTP 402.
