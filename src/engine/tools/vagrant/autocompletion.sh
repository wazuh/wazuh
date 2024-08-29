#!/bin/bash

wazuh-engine() {
	if (( $# < 1))
	then
		sudo /var/ossec/engine/wazuh-engine --help
	else
		sudo /var/ossec/engine/wazuh-engine $@
	fi
}

# Get the list of subcommands from the command's --help output
_subcommands() {
    wazuh-engine $@ --help | awk '/Subcommands:/,0 { if ( $1 != "Subcommands:" && $1 != "" ) {print $1}}'
}

_options() {
    wazuh-engine $@ --help | awk '/Options:/,/Subcommands:/ { if ( $1 ~ "--") {n=split($1,a,","); print a[n]}}'
}

_wazuh-engine_completion() {
	local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts=""

    if [[ ${prev} == --help ]]; then
        return 0
    fi

    if [[ -z $COMP_WORDS || ${#COMP_WORDS[@]} -eq 0 ]] ; then
        opts=$(_subcommands)
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi

    if [[ ${cur} == -* ]] ; then
        opts=$(_options ${COMP_WORDS[@]})
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi

    args=${COMP_WORDS[@]:1:COMP_CWORD}
    opts=$(_subcommands ${args})
    if [[ "${opts[@]}" == "" ]]; then
        opts=$(_options ${args})
    fi

    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
    return 0
}

complete -F _wazuh-engine_completion wazuh-engine
