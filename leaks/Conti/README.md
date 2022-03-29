# Conti leak IoCs

This is a git repo to organize IoCs and other tidbits that we extracted from the Conti leak.

## operator_wallets.csv
A csv file with all the bitcoin wallets we could extract from the leaked chat logs.
Wallets extracted via regex and checked against a wallet tracker

## scheduled_tasks_names.csv
A csv file with all the scheduled task names that we could extract from the leaked chat logs.
It seems that they are used for short periods and changed on a weekly basis (It was written in one of the chat logs)

## work_dirs.csv
A csv file with all the persistency working directories that we could extract from the leaked chat logs.
It seems that they are used for short periods and changed on a weekly basis (It was written in one of the chat logs)

## telegram_channels.txt
A list of telegram channels that Conti recommend following in one of their documentation manuals.