#!/usr/bin/bash
#Author: Bardiya Xhorshidi; The tool is under MIT License;

# koo means where; kooXSS means where is XSS!
# First replace values of each parameter with the payload.
# Then check if any of special chars like "<>' reflects in the response.
# We use the word kzw to recognize the chars in the response.

exit_code=$!
urls=$1


if [[ -z $1 ]]; then
    printf "[*] KooXss finds XSS vulnerabilities!\n"
    printf "[*] twitter.com/xbforce | github.com/xbforce\n"
    printf "[*] To run this tool you need to install urldedupe and sponge first."
    printf "[*] Usage: $0 urls.txt\n"
    exit 0
fi



timestamp() {
# CURRENT TIME
    date +"%m"/"%d"/"%y"-"%T"
}



printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
printf "[*] KooXss finds XSS vulnerabilities!\n"
printf "[*] twitter.com/xbforce | github.com/xbforce\n"
printf "[*] Usage: $0 <urls.txt>\n"
printf "[*] Depends on the amount of URLs, it may take some minutes or some hours to get\n    the job done, take care of your other jobs while KooXss is looking for XSS.\n"
printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"



start_time=$(printf "\nKooXss is started at: "
timestamp
printf "\n")
printf "$start_time\n"



function modifier_func {
    # MAKE URLs UNIQUE BASED ON THEIR PARAMETERS.
    urldedupe -u $1 | sponge $1 &&



    # MODIFY WAYBACK URLs. awk DECODEs URLs, OMIT FILES WITH SPECIFIC EXTENSIONS, REMOVE "=="
    # FROM END OF LINES, ADD "=1" IF LINES END WITH SINGLE "=" CHAR.
    cat $1 | awk -niord '{printf RT?$0chr("0x"substr(RT,2)):$0}' RS=%.. | grep -a -v ".jpg\|.jpeg\|.png\|.svg\|.css\|.js\|.gif\|.swf\|woff2" | grep -a -v "\[" | grep -a "=" | sed 's/==//g' | sed 's/=$/=1/' | awk '!a[$0]++' > can_be_deleted.del &&



    # GREP "=" THEN FOUR CHARS BEFORE "="
    grep_eq=$(cat can_be_deleted.del | grep -a -o -P '.{0,4}\=.{0,0}' | awk '!a[$0]++' > unique_params.del &)

    sleep 2 &&

    # READ THE MAIN FILE AND GREP UNIQUE CHARS FROM ABOVE FORLOOP.
    for up in $(cat unique_params.del); do

        cat can_be_deleted.del | grep -a ""$up"" | head -n 1 >> unique_urls.del &

    done &&
    cat unique_urls.del | awk '!a[$0]++' | sponge unique_urls.del &&



    for mod in $(cat unique_urls.del); do
        # COUNT NUMBER OF "=" CHAR IN EACH LINE, IF THERE IS ONLY ONE THEN REMOVE EVERYTHING
        # AFTER "=" AND SEND THE OUTPUT TO modified.del, ELIF SEND OTHER LINES TO modified.del
        count_eq=$(echo $mod | sed "s/=/=\n/g" | grep -a -c '=')
        if [[ $count_eq == "1" ]]; then
            echo $mod | sed "s/=[^=]*$/=/" >> modified.del
        elif [[ $count_eq != "1" ]]; then
            echo $mod >> modified.del
        fi

    done &&

    # awk REMOVES DUPLICATE LINES.
    cat modified.del | awk -F "[;,]" '!a[$1]++' | sponge modified.del


}
modifier_func $1 &&



# kooxss IS A TOOL FOR FINDING XSS VULNERABILITIES.
function kooxss_func {
    for r in $(cat modified.del); do

        (
        if [[ $r == *"."* ]]; then
            # COUNT NUMBER OF "=" IN EACH LINE
            count=$(echo $r | grep -a -o "=" -i | wc -l)
            for c in $count; do
                for s in $(seq 1 $c); do
                    echo $r | sed -E -e 's/=[^=&]*/=%7bkzw%22kzw%2522kzw%25%32%32kzw%3ckzw%253ckzw%25%33%63kzw%3ekzw%253ekzw%25%33%65kzw%27kzw/'$s

               done
            done
        fi
        )

    done | sort -u > kzw_payloads.del &&



    # GREP "=" THEN FOUR CHARS BEFORE "="
    cat kzw_payloads.del | grep -a -o -P '.{0,4}\=\%7b.{0,0}' | awk '!a[$0]++' > unique_kzw_params.del



    # READ THE MAIN FILE AND GREP UNIQUE CHARS FROM ABOVE FORLOOP.
    for ukp in $(cat unique_kzw_params.del); do

        cat kzw_payloads.del | grep -a ""$ukp"" | head -n 1 >> kooxss_payloads.del &

    done &&
    cat kooxss_payloads.del | awk '!a[$0]++' | sponge kooxss_payloads.del &&



    wordcount_kooxss_payload=$(wc -l < kooxss_payloads.del)
    printf "Number of URLs for kooxss: $wordcount_kooxss_payload\n" &&



    for u in $(cat kooxss_payloads.del); do
        (
        curlit=$(curl --silent --max-time 12 --url $u)
        # IF <"> ARE REFLECTED BEFORE THE WORD ```kzw``` IN THE RESPONSE THEN SAVE THE AFFECTED URL.
        if [[ $curlit == *'kzw<kzw'* ]] || [[ $curlit == *'kzw>kzw'* ]] || [[ $curlit == *'kzw"kzw'* ]]; then
            echo "$u" >> "possible_xss_$(date +'%Y_%m_%d').bug"
        elif [[ $curlit == *"kzw'kzw"* ]]; then
            echo "$u" >> "possible_xss_single_quote_$(date +'%Y_%m_%d').bug"
        fi
        ) &
        sleep 1.2
    done &&


    endtime=$(printf "\nKooXss finished at: "
    timestamp
    printf "\n")
    printf "$endtime\n"



    if [[ -f "possible_xss_$(date +'%Y_%m_%d').bug" ]]; then
        wordcount_possible_xss=$(wc -l < "possible_xss_$(date +'%Y_%m_%d').bug")
    fi &&
    #
    if [[ $wordcount_possible_xss == 0 ]] || [[ -z $wordcount_possible_xss ]]; then
        printf "Number of possible XSS: 0\n"
        printf "\n"
    else
        printf "Number of possible XSS: $wordcount_possible_xss\n"
        printf "\n"
    fi
}
kooxss_func &&


rm *.del

wait $exit_code
#UPDATE:10-may-2021

