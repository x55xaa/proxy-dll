"""Command Line Interface entry point."""

# Copyright (C) 2025  Stefano Cuizza

#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>.


from argparse import Namespace
import logging


logger = logging.getLogger(__name__)


def main(namespace: Namespace) -> None:
    """Main CLI function.

    Args:
        namespace:
          Namespace containing the command line parsing.
    """

    logger.debug('helloworld!')
    logger.info('helloworld!')
    logger.warning('helloworld!')
    logger.error('helloworld!')
    logger.critical('helloworld!')
