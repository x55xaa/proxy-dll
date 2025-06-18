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
import shutil
import sys
from typing import Any

import toml

from .modules import template
from .modules.rusty import cargo_new_lib, is_cargo_installed


logger = logging.getLogger(__name__)


def main(namespace: Namespace) -> None:
    """Main CLI function.

    Args:
        namespace:
          Namespace containing the command line parsing.
    """

    if not is_cargo_installed():
        logger.error('cargo is not installed. Please install Rust from https://www.rust-lang.org/tools/install.')

        sys.exit(1)

    if not cargo_new_lib(namespace.project):
        sys.exit(1)

    try:
        # create `build.rs`.
        with (namespace.project / 'build.rs').open('w+', encoding='utf-8') as f:
            f.write(template.get('build').render(**{
                'exported_symbols': namespace.exported_symbols,
                'dll_path': str(namespace.dll_path),
            }))

        # update `src/lib.rs`.
        with (namespace.project / 'src' / 'lib.rs').open('w+', encoding='utf-8') as f:
            f.write(template.get('lib').render())

        # update `Cargo.toml`.
        project_conf: dict[str, Any] = toml.load(namespace.project / 'Cargo.toml')

        project_conf['dependencies'] = {}
        project_conf['dependencies']['windows'] = {}
        project_conf['dependencies']['windows']['version'] = '0.*'
        project_conf['dependencies']['windows']['features'] = [
            'Win32_Foundation',
            'Win32_Security',
            'Win32_System_SystemServices',
            'Win32_System_Threading',
            'Win32_UI_WindowsAndMessaging',
        ]
        project_conf['dependencies']['windows-strings'] = {}
        project_conf['dependencies']['windows-strings']['version'] = '0.4'

        project_conf['lib'] = {}
        project_conf['lib']['crate-type'] = ['cdylib']  # https://doc.rust-lang.org/reference/linkage.html#r-link.cdylib.

        with (namespace.project / 'Cargo.toml').open('w+', encoding='utf-8') as f:
            toml.dump(project_conf, f)

        # update `toolchain.toml`.
        toolchain_conf: dict[str, Any] = {
            'toolchain': {
                'targets': ['x86_64-pc-windows-msvc']
            }
        }

        with (namespace.project / 'rust-toolchain.toml').open('w+', encoding='utf-8') as f:
            toml.dump(toolchain_conf, f)

    except Exception as e:
        shutil.rmtree(namespace.project)

        raise Exception from e
