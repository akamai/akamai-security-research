from db_connector.connector_factory import SUPPORTED_DBS, db_factory
from db_connector.neo4j_connector import RpcNeo4j
from etw_tracker.etw_tracker import EtwTracker

from getpass import getpass
import argparse
import sys


def parse_arguments() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db_host", help="IP or connection URL for the database")
    parser.add_argument("--db_type", help="Type of db to connect to", choices=SUPPORTED_DBS, default=SUPPORTED_DBS[0])
    parser.add_argument("--username", help="user name to use when connecting to the database")
    parser.add_argument("--password", help="password to use when connecting to the database")
    parser.add_argument("--save_host", help="save current host info to the database and exit", action='store_true')

    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    db_saver = db_factory(args.db_type)
    password = args.password if args.password else getpass("Please enter db password: ")
    db_saver.connect_to_db(args.db_host, args.username, password)

    if args.save_host:
        print("connected to database and saved host")
        exit(0)

    tracker = EtwTracker(db_saver)
    tracker.start_tracking()
    tracker.wait()


if __name__ == "__main__":
    main()
