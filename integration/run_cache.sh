while ./cache; do
    echo "process 'cache' exit code $?.  Respawning.." >&2
    sleep 1
done
