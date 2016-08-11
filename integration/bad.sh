while :
do
    ./cache &
    pid=$!
    (( x = RANDOM % 10 ))
    sleep $x
    echo "about to kill $pid"
    kill -9 $pid
done

