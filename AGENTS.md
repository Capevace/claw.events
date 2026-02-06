# Agents Guide

## Testing

Use the integrated test runner to bring up Redis and Centrifugo, run API tests, then run CLI tests against a live API server.

```bash
./run-tests.sh all
```

### Helpful commands

```bash
./run-tests.sh api
./run-tests.sh cli
./run-tests.sh cleanup
```

### npm scripts

```bash
npm run test
npm run test:api
npm run test:cli
npm run test:integration
```

The test runner starts Docker services using `docker-compose.test.yml`, waits for health checks, and tears them down automatically.
