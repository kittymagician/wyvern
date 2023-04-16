# wyvern - passive dns reconnaissance
<img src=https://github.com/kittymagician/wyvern/raw/main/wyvern.png width="100" height="100">

## Features
Google Public DNS Resolver - DNS Records (A, MX, TXT)

ipinfo - ASN enrichment

Shodan - CVEs

OpenAI - Report Writing*

## API Keys
In order to use wyvern you will need to obtain API keys from ipinfo, shodan and OpenAi. ipinfo has a nice free tier. Shodan has a one-off paid account that refreshes tokens every 30 days and OpenAi has a pay as you go service however you can set hard limits and during testing/development the cost has been roughly $5 for lots of test reports. 

## The Story
A weekend project to try and "push the boundries" of what's possible with automation of passive DNS with OpenAI.

## OpenAI
ChatGPT 3.5 ([text-davinci-003](https://platform.openai.com/docs/models/gpt-3-5)) is the model utilized by wyvern. The hard limit for this model is 4,097 tokens as such you may see report data cut off in the experimental report writing section as the model sometimes gets overloaded with the data being sent.  

\*Please note: OpenAI support is extremely buggy. The data that is being presented to wyvern is buggy at best. It is not a replacement for an analyst.
