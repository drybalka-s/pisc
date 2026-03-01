#!/bin/bash
# Public OCI-Image Security Checker
# Malware scanning module for OCI images using YARA
# Authors: @kapistka, https://github.com/drybalka-s 2026

# Usage
#     ./scan-yara.sh [-i image_link | --tar /path/to/private-image.tar]
# Available options:
#     --dont-output-result              don't output result into console, only into file
#     --ignore-errors                   ignore errors (instead, write to $ERROR_FILE)
#     -i, --image string                only this image will be checked. Example: -i r0binak/xzk8s:v1.1
#     --offline-feeds                   use a self-contained offline image with pre-downloaded yara-feeds (e.g., :latest-feeds)
#     --tar string                      check local image-tar. Example: --tar /path/to/private-image.tar

# Example
#     ./scan-yara.sh -i r0binak/xzk8s:v1.1

# To add custom yara rules, put file custom.yar in script directory or run ./scan.sh --yara-file

set -Eeo pipefail

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
# get exported var with default value if it is empty
: "${PISC_OUT_DIR:=/tmp}"
: "${PISC_YARA_CUSTOM_FILE:=$SCRIPTPATH/custom.yar}"
: "${PISC_FEEDS_DIR:=$PISC_OUT_DIR/.cache}"

IMAGE_DIR=$PISC_OUT_DIR'/image'
ERROR_FILE=$PISC_OUT_DIR'/yara.error'
RESULT_FILE=$PISC_OUT_DIR'/scan-yara.result'
YARA_RULES_DIR=$PISC_FEEDS_DIR'/yara'
YARA_RULES_FILE=$YARA_RULES_DIR'/rules.yar'
COMPILED_FILE=$YARA_RULES_DIR'/rules.yar.comp'
FEED_URL='https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip'
ZIP_FILE=$PISC_OUT_DIR'/yara-forge-rules-extended.zip'
UNPACK_DIR=$PISC_OUT_DIR'/unpacked'
SRC_IN_ZIP='packages/extended/yara-rules-extended.yar'

EXP_DAY="6"
IMAGE_LINK=''
IS_ERROR=false
IS_EXLUDED=false
LOCAL_FILE=''
OFFLINE_FEEDS=false
DONT_OUTPUT_RESULT=false

C_RED='\033[0;31m'
C_NIL='\033[0m'

EMOJI_MALWARE='\U1F344' # mushroom
EMOJI_DEFAULT='\U1F4A9' # shit
EMOJI_EXCLUDE='\U1F648' # see-no-evil monkey
EMOJI_OK='\U1F44D' # thumbs up
EMOJI_NAMES=(
    'vulnerabil'
    'ploit'
    'meter'
    'crypto'
    'miner'
    'mining'
    'hack'
    'tool'
    'backdoor'
    'trojan'
    'worm'
    'virus'
)
EMOJI_CODES=(
    '\U1F41E' # bug
    '\U1F419' # octopus
    '\U1F419' # octopus
    '\U1F511' # key
    '\U1F4B0' # money
    '\U1F4B0' # money
    '\U1F47E' # alien
    '\U1F47E' # alien
    '\U1F434' # horse
    '\U1F434' # horse
    '\U1F41B' # worm
    '\U1F9EC' # dna
)

eval "rm -f $RESULT_FILE $ERROR_FILE"

DEBUG_BASH=''
DEBUG_CURL='-sf'
DEBUG_UNZIP='-qq'
if [[ "$-" == *x* ]]; then
    DEBUG_BASH='-x '
    DEBUG_CURL=''
    DEBUG_UNZIP=''
fi
# silent mode for external tools if not debug
debug_null() {
    if [[ "$-" != *x* ]]; then 
        eval &>/dev/null
    fi    
}

# exception handling
error_exit()
{
    if  [ "$IS_ERROR" = false ]; then
        IS_ERROR=true
        if [ "$IGNORE_ERRORS" = true ]; then
            printf "   $1" > $ERROR_FILE
            return 0
        else
            echo "  $IMAGE_LINK >>> $1                    "
            exit 2
        fi
    fi
}

# read the options
ARGS=$(getopt -o i: --long dont-output-result,ignore-errors,image:,offline-feeds,tar: -n $0 -- "$@")
eval set -- "$ARGS"

# extract options and their arguments into variables.
while true ; do
    case "$1" in
        --dont-output-result)
            case "$2" in
                "") shift 1 ;;
                *) DONT_OUTPUT_RESULT=true ; shift 1 ;;
            esac ;;
        --ignore-errors)
            case "$2" in
                "") shift 1 ;;
                *) IGNORE_ERRORS=true ; shift 1 ;;
            esac ;;
        -i|--image)
            case "$2" in
                "") shift 2 ;;
                *) IMAGE_LINK=$2 ; shift 2 ;;
            esac ;;
        --offline-feeds)
            case "$2" in
                "") shift 1 ;;
                *) OFFLINE_FEEDS=true ; shift 1 ;;
            esac ;;
        --tar)
            case "$2" in
                "") shift 2 ;;
                *) LOCAL_FILE=$2 ; shift 2 ;;
            esac ;;
        --) shift ; break ;;
        *) echo "Wrong usage! Try '$0 --help' for more information." ; exit 2 ;;
    esac
done

# check image name exclusion before
if [ -z "$LOCAL_FILE" ]; then
    # check * pattern (12345abcd) for IMAGE_LINK
    set +e
    /bin/bash $DEBUG$SCRIPTPATH/check-exclusions.sh -i $IMAGE_LINK --malware 12345abcd
    if [[ $? -eq 1 ]] ; then
        if [ "$DONT_OUTPUT_RESULT" == "false" ]; then
            echo -e "$IMAGE_LINK >>> OK (whitelisted)                      "
        fi    
        echo "OK (whitelisted)" > $RESULT_FILE
        exit 0
    fi
    set -e 
fi

# download and unpack image or use cache
if [ ! -z "$LOCAL_FILE" ]; then
    IMAGE_LINK=$LOCAL_FILE
    /bin/bash $DEBUG_BASH$SCRIPTPATH/scan-download-unpack.sh --tar $LOCAL_FILE
else
    /bin/bash $DEBUG_BASH$SCRIPTPATH/scan-download-unpack.sh -i $IMAGE_LINK
fi

IS_CACHED=false
if [ -s "$YARA_RULES_FILE" ]; then
    # check offline mode
    if [ "$OFFLINE_FEEDS" = true ] ; then
        IS_CACHED=true
    else
        # check date creation (birth)
        if [ $(($(date +%s) - $(stat -c %W "$YARA_RULES_FILE"))) -le 90000 ]; then
            IS_CACHED=true
        fi
    fi    
fi

# upadate rules if not cached
if  [ "$IS_CACHED" = false ]; then
    rm -f "$YARA_RULES_FILE"
    rm -rf "$UNPACK_DIR"
    mkdir -p "$UNPACK_DIR"
    echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> download YARA rules\033[0K\r"
    curl  $DEBUG_CURL -L "$FEED_URL" -o "$ZIP_FILE" \
        || error_exit "yara: error download $FEED_URL"
    mkdir -p "$YARA_RULES_DIR"
    unzip $DEBUG_UNZIP -o "$ZIP_FILE" -d "$UNPACK_DIR" \
        || error_exit "yara: error unzip $ZIP_FILE"
    mv -f "$UNPACK_DIR/$SRC_IN_ZIP" "$YARA_RULES_FILE"
    echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> compile YARA rules\033[0K\r"
    yarac "$YARA_RULES_FILE" "$COMPILED_FILE"
fi

# unpack tar to image/0 and get list of files
unpack() {
    echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> unpack layer $FILES_COUNTER/$FILES_TOTAL\033[0K\r"
    # unpack the layer into a folder
    # sometimes rm and tar occurs an error
    # therefore disable error checking
    set +Eeo pipefail
    `rm -rf "$IMAGE_DIR/0"` debug_null
    `mkdir "$IMAGE_DIR/0"` debug_null
    # if you run tar embedded in alpine (OCI-image based on alpine)
    # then there is a tar of a different version (busybox) and occurs errors when unpacking
    # unreadable files, (in this place unreadable files may occur)
    # which causes the script to stop.
    # Therefore, it is necessary to additionally install GNU-tar in the alpine-OCI-image
    # Also exclude dev/* because nonroot will cause a device creation error
    eval tar --ignore-failed-read --one-file-system --no-same-owner --no-same-permissions --mode=+w --exclude dev/* -xf "$1" -C "$IMAGE_DIR/0" $DEBUG_TAR
    # if directories after extraction lack the "w" attribute, deletion will result in a "Permission denied" error.
    # Therefore, we add the "rwx" attribute to the directories
    find "$IMAGE_DIR/0" -type d -exec chmod u+rwx {} + 2>/dev/null
    # turning error checking back on
    set -Eeo pipefail    
}

# scan $IMAGE_DIR/0 directory
yara_scan() {
    echo -ne "  $(date +"%H:%M:%S") $IMAGE_LINK >>> scan YARA $FILES_COUNTER/$FILES_TOTAL\033[0K\r"
    RES=$PISC_OUT_DIR/${filename:0:8}.yl
    yara -rfmC "$COMPILED_FILE" "$IMAGE_DIR/0" > "$RES" 2>/dev/null
    if [ -s "$PISC_YARA_CUSTOM_FILE" ]; then
        yara -rfm "$PISC_YARA_CUSTOM_FILE" "$IMAGE_DIR/0" >> "$RES" 2>/dev/null
    fi
    if [[ -s "$RES" ]] ; then
        # print magic
        # all descriptions to file by line
        sed -n 's/.*description="\([^"]*\)".*/\1/p' $RES > $RES.2
        
        # add emoji to descriptions
        shopt -s nocasematch
        while IFS= read -r line; do
            new="$line"
            IS_EMOJI=false
            for (( jj=0; jj<${#EMOJI_NAMES[@]}; jj++ ));
            do
                if [[ $line =~ ${EMOJI_NAMES[$jj]} ]]; then
                    new=${EMOJI_CODES[$jj]}' '$line
                    IS_EMOJI=true
                    break
                fi
            done
            if [ "$IS_EMOJI" = false ]; then
                new=$EMOJI_DEFAULT' '$line
            fi
            printf '%s\n' "$new"
        done < "$RES.2" > "$RES.3" && mv "$RES.3" "$RES.2"

        # all paths to file by line
        awk '{print $NF}' $RES > $RES.3
        # cut paths
        sed "s|^$IMAGE_DIR/0||" "$RES.3" > "$RES.4" && mv "$RES.4" "$RES.3"
        # all paths and descriptions to file by line
        paste $RES.3 $RES.2 > $RES.4

        # check exclusions
        touch "$RES.5"
        set +e
        while IFS= read -r line2; do
            /bin/bash $DEBUG$SCRIPTPATH/check-exclusions.sh -i $IMAGE_LINK --yara "$line2"
            if [[ $? -eq 1 ]] ; then
                IS_EXLUDED=true
            else    
                printf '%s\n' "$line2" >> "$RES.5"
            fi
        done < "$RES.4"
        set -e
        mv "$RES.5" "$RES.4"

        # continue if any detections
        if [[ -s "$RES.4" ]] ; then
            sort -t $'\t' -k1,1 $RES.4 > $RES.5
            awk -F'\t' -v layer="  layer:${filename:0:8}" 'BEGIN{print layer}{if($1!=p){print "     "$1; p=$1} print "       "$2}' "$RES.5" > "$RES"
            cat $RES >> $RESULT_FILE
            rm -f $RES $RES.2 $RES.3 $RES.4 $RES.5 2>/dev/null
        else
            # remove layer result if it's clear after exlusions
            rm -f $RES $RES.2 $RES.3 $RES.4 2>/dev/null
        fi
    else
        # remove layer result if it's clear
        rm "$RES"
    fi
}

# unpack every layer and scan it yara
FILES=("$IMAGE_DIR"/*.tar)
FILES_TOTAL=${#FILES[@]}
FILES_COUNTER=0
for f in "${FILES[@]}"; 
do
    FILES_COUNTER=$((FILES_COUNTER+1))
    filename="${f##*/}"
    filename="${filename%.*}"
    unpack $f
    yara_scan
done

# generating result
RESULT_MESSAGE=''
if [ -s "$RESULT_FILE" ]; then
    RESULT_MESSAGE=$(<$RESULT_FILE)
    RESULT_MESSAGE="$EMOJI_MALWARE $C_RED$IMAGE_LINK$C_NIL >>> yara detected malicious file"$'\n'$RESULT_MESSAGE
    if [ "$IS_EXLUDED" == "true" ]; then
        RESULT_MESSAGE=$RESULT_MESSAGE'\n'"$EMOJI_EXCLUDE some yara detections are whitelisted"
    fi
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then
        echo -e "$RESULT_MESSAGE"
    fi    
    echo "$RESULT_MESSAGE" > $RESULT_FILE
else
    if [ "$DONT_OUTPUT_RESULT" == "false" ]; then
        if [ "$IS_EXLUDED" == "true" ]; then
            echo -e "$IMAGE_LINK >>> OK (whitelisted)                      "
        else
            echo -e "$IMAGE_LINK >>> OK                                    "
        fi    
    fi    
    echo "OK" > $RESULT_FILE
    if [ "$IS_EXLUDED" == "true" ]; then
        echo "OK (whitelisted)" > $RESULT_FILE
    else
        echo "OK" > $RESULT_FILE
    fi   
fi

exit 0
