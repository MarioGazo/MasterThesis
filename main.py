"""
Project for Master Thesis Spring 2023 at DTU

Topic:
    Analysis and comparison of short-lived data authentication protocols

Author:
    - Mário Gažo (s212687@student.dtu.dk)
"""
from argparse import ArgumentParser, Namespace
from typing import Callable

from src.experiments import *


def parse_args() -> Namespace:
    """ Parse command line arguments """
    argumentParser: ArgumentParser = ArgumentParser(prog='main.py')
    argumentParser.add_argument(
        'experiment',
        type=str,
        help='Specify which scheme do you want to conduct experiments for.',
        choices=SCHEMES.keys()
    )
    return argumentParser.parse_args()


def run_experiments(suite: [Callable]) -> None:
    """ Runs the provided experiment suite """
    for i, exp in enumerate(suite):
        print(f"{i + 1}/{len(suite)}:\t{exp.__name__}")
        exp()


SCHEMES: {} = {
    'TDS': expTDS,
    'ES': expES
}
""" Possible experiment suites to run """


def main():
    """ Main function of the project, here the experiments are chosen and run """
    args: Namespace = parse_args()
    run_experiments(SCHEMES[args.experiment])


if __name__ == "__main__":
    main()
