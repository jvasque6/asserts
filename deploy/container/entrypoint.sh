python3 /exploit.py > /tmp/fluidasserts.log
retval=$?
cat /tmp/fluidasserts.log
curl -u ${USER}:${PASS} -T /tmp/fluidasserts.log https://fluid.jfrog.io/fluid/generic/fluidasserts_${ORG}_${APP}_$(date +%Y%m%d%H%M%S).log
exit $retval
