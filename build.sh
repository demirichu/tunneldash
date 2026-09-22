#!/bin/bash
docker run --rm -v "$PWD:/app" -w /app mcr.microsoft.com/dotnet/sdk:10.0-resolute bash -c "apt-get update && apt-get install -y clang zlib1g-dev && dotnet publish -c Release -r linux-x64 /p:PublishAot=true /p:StripSymbols=true -o ./publish"
