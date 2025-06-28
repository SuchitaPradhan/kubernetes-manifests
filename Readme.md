<!-- kubectl taint nodes worker-node1 environment=dev:NoSchedule -->

kubectl taint nodes ip-192-168-57-127.ap-south-1.compute.internal environment=dev

Command to remove taint from the node

kubectl taint node <node-name> environment=dev:NoSchedule- 

apiVersion: v1
kind: Pod
metadata:
  name: nginx-test
  labels:
    env: test-env
spec:
  containers:
  - name: nginx
    image: nginx:latest
    imagePullPolicy: IfNotPresent
    resources:
      requests:
        memory: "128Mi"
        cpu: "250m"
      limits:
        memory: "512Mi"
        cpu: "500m"
  tolerations:
  - key: "gpu"
    operator: "Equal"
    value: "true"
    effect: "NoSchedule"