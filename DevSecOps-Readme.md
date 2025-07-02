```yaml

# 1. Synk 

# Connecting the public and private repoistry and test reports.

# 2 Trivy
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
trivy image nginx:latest
trivy fs . 

# Secrets and ConfigMap 

apiVersion: v1
kind: Secret
metadata:
  name: mongodb-secret
  namespace: cloudchamp
data:
  username: YWRtaW4=
  password: cGFzc3dvcmQ=


# Configmap

apiVersion: v1
kind: ConfigMap
metadata:
  name: testing-config
data:
  NAME: "Sibasish"

# Sealed Secrets

kubectl create ns sealed-secrets 

helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets

helm install sealed-secrets -n sealed-secrets --set-string fullnameOverride=sealed-secrets-controller sealed-secrets/sealed-secrets

# Installing Kubeseal

# Fetch the latest sealed-secrets version using GitHub API
KUBESEAL_VERSION=$(curl -s https://api.github.com/repos/bitnami-labs/sealed-secrets/tags | jq -r '.[0].name' | cut -c 2-)

# Check if the version was fetched successfully
if [ -z "$KUBESEAL_VERSION" ]; then
    echo "Failed to fetch the latest KUBESEAL_VERSION"
    exit 1
fi

curl -OL "https://github.com/bitnami-labs/sealed-secrets/releases/download/v${KUBESEAL_VERSION}/kubeseal-${KUBESEAL_VERSION}-linux-amd64.tar.gz"
tar -xvzf kubeseal-${KUBESEAL_VERSION}-linux-amd64.tar.gz kubeseal
sudo install -m 755 kubeseal /usr/local/bin/kubeseal

# Applying to Seal the secrets:- 

kubeseal --fetch-cert --controller-name sealed-secrets-controller --controller-namespace sealed-secrets

kubectl create secret generic secret-name --dry-run=client --from-literal=foo=bar --from-literal=key1=value -o yaml | \
  kubeseal --controller-name=sealed-secrets-controller --controller-namespace=sealed-secrets --format=yaml > mysealedsecret.yaml

# If you want to use a file with to create secret. 

kubeseal --controller-name=sealed-secrets-controller --controller-namespace=sealed-secrets --format=yaml < secret.yaml > sealed-secret.yaml

# Kube Bench

vi job.yaml 

---
apiVersion: batch/v1
kind: Job
metadata:
  name: kube-bench
spec:
  template:
    metadata:
      labels:
        app: kube-bench
    spec:
      containers:
        - command: ["kube-bench"]
          image: docker.io/aquasec/kube-bench:v0.11.1
          name: kube-bench
          volumeMounts:
            - name: var-lib-cni
              mountPath: /var/lib/cni
              readOnly: true
            - mountPath: /var/lib/etcd
              name: var-lib-etcd
              readOnly: true
            - mountPath: /var/lib/kubelet
              name: var-lib-kubelet
              readOnly: true
            - mountPath: /var/lib/kube-scheduler
              name: var-lib-kube-scheduler
              readOnly: true
            - mountPath: /var/lib/kube-controller-manager
              name: var-lib-kube-controller-manager
              readOnly: true
            - mountPath: /etc/systemd
              name: etc-systemd
              readOnly: true
            - mountPath: /lib/systemd/
              name: lib-systemd
              readOnly: true
            - mountPath: /srv/kubernetes/
              name: srv-kubernetes
              readOnly: true
            - mountPath: /etc/kubernetes
              name: etc-kubernetes
              readOnly: true
            - mountPath: /usr/local/mount-from-host/bin
              name: usr-bin
              readOnly: true
            - mountPath: /etc/cni/net.d/
              name: etc-cni-netd
              readOnly: true
            - mountPath: /opt/cni/bin/
              name: opt-cni-bin
              readOnly: true
      hostPID: true
      restartPolicy: Never
      volumes:
        - name: var-lib-cni
          hostPath:
            path: /var/lib/cni
        - hostPath:
            path: /var/lib/etcd
          name: var-lib-etcd
        - hostPath:
            path: /var/lib/kubelet
          name: var-lib-kubelet
        - hostPath:
            path: /var/lib/kube-scheduler
          name: var-lib-kube-scheduler
        - hostPath:
            path: /var/lib/kube-controller-manager
          name: var-lib-kube-controller-manager
        - hostPath:
            path: /etc/systemd
          name: etc-systemd
        - hostPath:
            path: /lib/systemd
          name: lib-systemd
        - hostPath:
            path: /srv/kubernetes
          name: srv-kubernetes
        - hostPath:
            path: /etc/kubernetes
          name: etc-kubernetes
        - hostPath:
            path: /usr/bin
          name: usr-bin
        - hostPath:
            path: /etc/cni/net.d/
          name: etc-cni-netd
        - hostPath:
            path: /opt/cni/bin/
          name: opt-cni-bin

kubectl get pods

kubectl logs -f <pod_name>


# Falco. 

helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm install --replace falco --namespace falco --create-namespace --set tty=true falcosecurity/falco

kubectl create deployment nginx --image=nginx
kubectl exec -it $(kubectl get pods --selector=app=nginx -o name) -- cat /etc/shadow
kubectl logs -l app.kubernetes.io/name=falco -n falco -c falco | grep Warning


#Falco Custom Rule:- 
customRules:
  custom-rules.yaml: |-
    - rule: Write below etc
      desc: An attempt to write to /etc directory
      condition: >
        (evt.type in (open,openat,openat2) and evt.is_open_write=true and fd.typechar='f' and fd.num>=0)
        and fd.name startswith /etc
      output: "File below /etc opened for writing | file=%fd.name pcmdline=%proc.pcmdline gparent=%proc.aname[2] ggparent=%proc.aname[3] gggparent=%proc.aname[4] evt_type=%evt.type user=%user.name user_uid=%user.uid user_loginuid=%user.loginuid process=%proc.name proc_exepath=%proc.exepath parent=%proc.pname command=%proc.cmdline terminal=%proc.tty"
      priority: WARNING
      tags: [filesystem, mitre_persistence]    


helm upgrade --namespace falco falco falcosecurity/falco --set tty=true -f falco_custom_rules_cm.yaml
kubectl exec -it $(kubectl get pods --selector=app=nginx -o name) -- touch /etc/test_file_for_falco_rule
kubectl exec -it $(kubectl get pods --selector=app=nginx -o name) -- touch /etc/test_file_for_falco_rule

```
