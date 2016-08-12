while :
do
    ./cache &
    pid=$!
    echo "started $pid"
    (( x = RANDOM % 10 ))
    sleep $x
    echo "killing $pid"
    kill -9 $pid
done

