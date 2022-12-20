# hexlink-verifier
## Project Setup

```sh
npm install
```

### Compile and build typescript to js
```sh
npm run build
```

### Start function emulators for local testing
```sh
npm run serve
```

### Deploy to firebase with production env
```sh
npm run deploy
```
Note: Select "N" for the question "Would you like to proceed with deletion? Selecting no will continue the rest of the deployments" while deploying the functions. 

## Troubleshooting
1. Remember to build the project before serving/deploying to include your code changes
2. If you are adding new functions, you will need deploy it first otherwise emulators won't pick up the change
3. Ensure doppler is properly set up and it's reading secrets correctly. You can manually run `doppler secrets download --no-file | jq '{doppler: .}'` at your terminal to check
