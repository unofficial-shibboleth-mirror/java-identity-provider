#!/usr/bin/env bash

declare LOCATION

LOCATION=$(dirname $0)

$LOCATION/runclass.sh net.shibboleth.idp.installer.plugin.impl.PluginInstallerCLI --home "$LOCATION/.." "$@"
