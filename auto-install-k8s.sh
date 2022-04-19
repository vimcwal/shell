#!/usr/bin/bash
#source /tmp/env
############################################################
check_moudle=( ip_vs
ip_vs_lc 
ip_vs_wlc 
ip_vs_rr 
ip_vs_wrr 
ip_vs_lblc 
ip_vs_lblcr 
ip_vs_dh 
ip_vs_sh 
ip_vs_fo 
ip_vs_nq 
ip_vs_sed 
ip_vs_ftp 
ip_vs_sh 
nf_conntrack 
ip_tables 
ip_set xt_set 
ipt_set
ipt_rpfilter
ipt_REJECT
ipip
overlay
br_netfilter 
)

URL_LIST=( http://download.lsythink.online/dl/cfssl/cfssl-certinfo_1.6.1_linux_amd64
http://download.lsythink.online/dl/cfssl/cfssl_1.6.1_linux_amd64
http://download.lsythink.online/dl/cfssl/cfssljson_1.6.1_linux_amd64
http://download.lsythink.online/dl/kubernetes_1.23.5/cri-containerd-cni-1.6.1-linux-amd64.tar.gz
http://download.lsythink.online/dl/kubernetes_1.23.5/etcd-v3.5.2-linux-amd64.tar.gz
http://download.lsythink.online/dl/kubernetes_1.23.5/kubernetes-server-linux-amd64.tar.gz
http://download.lsythink.online/dl/kubernetes_1.23.5/nginx_1.20.tar.gz
http://download.lsythink.online/dl/kubernetes_1.23.5/runc.amd64
http://download.lsythink.online/dl/scripts/check_port.sh
http://download.lsythink.online/dl/scripts/calico_other.yaml
http://download.lsythink.online/dl/scripts/rbac-dashboard.yaml
http://download.lsythink.online/dl/scripts/dashboard-k8s.yaml
http://download.lsythink.online/dl/scripts/metric-server.yaml
http://download.lsythink.online/dl/scripts/calico.yaml
http://download.lsythink.online/dl/scripts/coreDNS.yaml
)

#临时存放下载软件的目录
tmp_path='/tmp/soft'
        cert_path=$tmp_path/cert
        [ -e $cert_path ] || mkdir -p $cert_path


USER='root'
PASSWORD='    '
PORT=22


# 生成 EncryptionConfig 所需的加密 key
export ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)


# 集群各机器 IP 数组
export NODE_IPS=( 192.168.30.250 192.168.30.249 192.168.30.248 )
# 集群各 IP 对应的主机名数组
export NODE_NAMES=(k8s-01 k8s-02 k8s-03 )


# 集群MASTER机器 IP 数组
export MASTER_IPS=( 192.168.30.250 192.168.30.249 192.168.30.248 )
# 集群所有的master Ip对应的主机
export MASTER_NAMES=(k8s-01 k8s-02 k8s-03)

# etcd 集群服务地址列表
export ETCD_ENDPOINTS="https://192.168.30.250:2379,https://192.168.30.249:2379,https://192.168.30.248:2379"
# etcd 集群间通信的 IP 和端口
export ETCD_NODES="k8s-01=https://192.168.30.250:2380,k8s-02=https://192.168.30.249:2380,k8s-03=https://192.168.30.248:2380"
# etcd 集群所有node ip
export ETCD_IPS=(192.168.30.250 192.168.30.249 192.168.30.248)
# etcd 数据目录
export ETCD_DATA_DIR="/data/k8s/etcd/data"
# etcd WAL 目录，建议是 SSD 磁盘分区，或者和 ETCD_DATA_DIR 不同的磁盘分区
export ETCD_WAL_DIR="/data/k8s/etcd/wal"



# kube-apiserver 的反向代理(kube-nginx)地址端口
export KUBE_APISERVER="192.168.30.54"
export KUBE_APISERVER_PORT="8443"
export KEEPALIVED_VIP='192.168.30.250'


# 节点间互联网络接口名称
export IFACE="ens33"


#节点ip
export LOCAL_IP=`ip a s "$IFACE" | grep "inet" | grep -v 'inet6' | sed -r 's#.*inet (.*)/.*#\1#'`



# k8s 各组件数据目录
export K8S_DIR="/data/k8s/k8s"

#k8s各组件配置文件目录
export K8S_CONF_DIR="/etc/kubernetes"

# docker 数据目录
#export DOCKER_DIR="/data/k8s/docker"
## 以下参数一般不需要修改
# TLS Bootstrapping 使用的 Token，可以使用命令 head -c 16 /dev/urandom | od -An -t x | tr -d ' ' 生成
#BOOTSTRAP_TOKEN="41f7e4ba8b7be874fcff18bf5cf41a7c"
# 最好使用 当前未用的网段 来定义服务网段和 Pod 网段
# 服务网段，部署前路由不可达，部署后集群内路由可达(kube-proxy 保证)
SERVICE_CIDR="10.254.0.0/16"
# Pod 网段，建议 /16 段地址，部署前路由不可达，部署后集群内路由可达(flanneld 保证)
CLUSTER_CIDR="172.30.0.0/16"
# 服务端口范围 (NodePort Range)
export NODE_PORT_RANGE="1024-32767"
# flanneld 网络配置前缀
export FLANNEL_ETCD_PREFIX="/kubernetes/network"
# kubernetes 服务 IP (一般是 SERVICE_CIDR 中第一个IP)
export CLUSTER_KUBERNETES_SVC_IP="10.254.0.1"
# 集群 DNS 服务 IP (从 SERVICE_CIDR 中预分配)
export CLUSTER_DNS_SVC_IP="10.254.0.2"
# 集群 DNS 域名（末尾不带点号）
export CLUSTER_DNS_DOMAIN="cluster.local"
# 将二进制目录 /opt/k8s/bin 加到 PATH 中
export PATH=/opt/k8s/bin:$PATH


############################################################



init_os(){
	which jq &>/dev/null
	[ $? -eq 0 ] || yum install -y jq
	error_file='/tmp/check_os_result.txt'
	#判断内核是否满足
	kernel_version=`uname -r | awk -F '.' '{print $1}'`
		if [ $kernel_version -eq 3 ];then
			echo "`uname -r` 内核版本过低" >> ${error_file}
		fi


	#检查模块是否加载
	for moudle in ${check_moudle[@]};do
		lsmod | awk '{print $1}' | grep -w $moudle &>/dev/null
		if [ $? -ne 0 ];then
			#尝试再次加载模块
			modprobe ${moudle} &>/dev/null
			#判断是否成功
			if [ $? -ne 0 ];then
				echo "缺少 ${moudle}" >> ${error_file}
				break
			fi

		fi
	done

	#判断是否成功
	[ -e ${error_file} ] &&  exit
	#初始化系统
#	ls /etc/yum.repos.d/ | grep -e epel -e CentOS-Base &>/dev/null
#	if [ $? -ne 0 ];then
#		wget -O /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/epel-7.repo  &> /dev/null
#		curl -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo &> /dev/null
#	fi

	which expect &> /dev/null

	[ $? -eq 0 ] || yum install -y sshpass expect &> /dev/null

	#判断是否安装成功
	which expect &> /dev/null
	if [ $? -eq 0 ];then
		#分发公钥

		[ -e /root/.ssh/id_rsa ] || ssh-keygen -t rsa -P "" -f /root/.ssh/id_rsa
		for i in ${NODE_IPS[@]};do 
		expect -c "
		spawn ssh-copy-id -i /root/.ssh/id_rsa.pub root@$i
				expect {
						\"*yes/no*\" {send \"yes\r\"; exp_continue}
						\"*password*\" {send \"${PASSWORD}\r\"; exp_continue}
						\"*Password*\" {send \"${PASSWORD}\r\";}
				} "
				
		done 
		
	else
		echo "expect 安装失败"
		exit 1
	fi

}

#设置hosts主机名,分发主机名
init_hosts(){
	>/tmp/tmp_hosts
	for num in $(seq 0 `awk "BEGIN{print("${#NODE_IPS[@]}"-1)}"`);do
		name=${NODE_NAMES[$num]}
		#生成hosts文件
		echo ${NODE_IPS[${num}]} $name >>/tmp/tmp_hosts
		#设置主机名
		ssh $USER@${NODE_IPS[${num}]} -p $PORT "hostnamectl set-hostname ${name}"

	done
	for ip in ${NODE_IPS[@]};do
		scp -r -P $PORT /tmp/tmp_hosts  $USER@$ip:/tmp
		ssh $USER@$ip -p $PORT "cat /tmp/tmp_hosts >> /etc/hosts" 
	done
}

download_soft(){
	 [ -e $tmp_path ] || mkdir -p $tmp_path
	#下载所有文件
	for url in ${URL_LIST[@]};do
		wget $url -O $tmp_path/`basename $url`
		[ $? -ne 0 ] && echo " $url 下载失败" && exit
		echo "$url 下载成功"
	done
}

install_cfssl(){
	cd $tmp_path &&\
	#安装工具
	which cfssl &> /dev/null
	if [ $? -ne 0 ];then
		mv cfssl_1.6.1_linux_amd64 cfssl &&\
		mv cfssljson_1.6.1_linux_amd64 cfssljson &&\
		mv cfssl-certinfo_1.6.1_linux_amd64 cfssl-certinfo &&\
		mv cfssl* /usr/local/bin/
		chmod a+x /usr/local/bin/cfssl /usr/local/bin/cfssljson /usr/local/bin/cfssl-certinfo 
	fi

	which cfssl &> /dev/null
	[ $? -ne 0 ]  &&  (echo "安装cfssl失败" && exit)
}


#########################################证书相关###################################3
#创建CA根证书

init_ca_cert(){
	[ -e $K8S_CONF_DIR/cert ] || mkdir -p $K8S_CONF_DIR/cert


	#创建证书存放目录
	cert_path=$tmp_path/cert
	[ -e $cert_path ] || mkdir -p $cert_path

	cat > $cert_path/ca-csr.json <<-EOF

	{
	  "CN": "kubernetes",
	  "key": {
		"algo": "rsa",
		"size": 2048
	  },
	  "names": [
		{
		  "C": "CN",
		  "ST": "BeiJing",
		  "L": "BeiJing",
		  "O": "k8s",
		  "OU": "System"
		}
	  ],
	  "ca": {
		"expiry": "876000h"
	 }
	}
	EOF
	#生成证书模板
	cat >$cert_path/ca-config.json <<-EOF
	 
	 {
	  "signing": {
		"default": {
		  "expiry": "876000h"
		},
		"profiles": {
		  "kubernetes": {
			"usages": [
				"signing",
				"key encipherment",
				"server auth",
				"client auth"
			],
			"expiry": "876000h"
		  }
		}
	  }
	}

	EOF
	#生成根证书
	cd $cert_path &&\
	cfssl gencert -initca ca-csr.json | cfssljson -bare ca
	#cp ca* $K7S_CONF_DIR/cert

	#签发所有的证书，由该节点进行分发

	#生成etcd证书
	[ -e $cert_path/etcd_cert ] || mkdir -p $cert_path/etcd_cert

	#获取etcd所有节点ip
	tmp_ips=''
	for i in $(seq 0 `awk "BEGIN{print("${#ETCD_IPS[@]}"-1)}"`);do

		if [ ${ETCD_IPS[$i]} == ${ETCD_IPS[-1]} ];then
			tmp_ips+=\"${ETCD_IPS[$i]}\"
		else
			tmp_ips+=\"${ETCD_IPS[$i]}\",
		fi
	done

		#签发证书
		cat > $cert_path/etcd-csr.json<<-EOF

	{
	  "CN": "etcd",
	  "hosts": [
		"127.0.0.1",
		${tmp_ips}
	  ],
	  "key": {
		"algo": "rsa",
		"size": 2048
	  },
	  "names": [
		{
		  "C": "CN",
		  "ST": "BeiJing",
		  "L": "BeiJing",
		  "O": "k8s",
		  "OU": "System"
		}
	  ]
	}
	EOF
		#生成CA证书
		cd  $cert_path &&\
		cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes etcd-csr.json | cfssljson -bare etcd
	#	cp -r etcd* $K8S_CONF_DIR/etcd/cert
		mv etcd* $cert_path/etcd_cert

	#########################################################
	#生成apiserver证书

	#获取apiserver所有节点ip
	tmp_ips=''
	for i in $(seq 0 `awk "BEGIN{print("${#MASTER_IPS[@]}"-1)}"`);do

		if [ ${MASTER_IPS[$i]} == ${MASTER_IPS[-1]} ];then
			tmp_ips+=\"${MASTER_IPS[$i]}\"
		else
			tmp_ips+=\"${MASTER_IPS[$i]}\",
		fi
	done


	[ -e $cert_path/kubernetes_cert ] || mkdir -p $cert_path/kubernetes_cert


	cat > $cert_path/kube-apiserver-csr.json <<-EOF

	{
	  "CN": "kubernetes",
	  "hosts": [
		"127.0.0.1",
		"${KUBE_APISERVER}",
		"${CLUSTER_KUBERNETES_SVC_IP}",
		"kubernetes",
		"kubernetes.default",
		"kubernetes.default.svc",
		"kubernetes.default.svc.cluster",
		"kubernetes.default.svc.cluster.local",
		${tmp_ips}
		
	  ],
	  "key": {
		"algo": "rsa",
		"size": 2048
	  },
	  "names": [
		{
		  "C": "CN",
		  "ST": "BeiJing",
		  "L": "BeiJing",
		  "O": "k8s",
		  "OU": "System"
		}
	  ]
	}
	EOF
		
	cd $cert_path &&\
	cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-apiserver-csr.json | cfssljson -bare kube-apiserver

	#token文件
	#####################
	echo "`head -c 16 /dev/urandom | od -An -t x | tr -d ' '`,kubelet-bootstrap,10001,\"system:kubelet-bootstrap\"" > token.csv

	mv kube-apiserver* token.csv $cert_path/kubernetes_cert	




	################################################
	#生成kubectl的证书

	[ -e $cert_path/kubectl_cert ] || mkdir -p $cert_path/kubectl_cert

	cat >$cert_path/admin-csr.json<<-EOF 
	{
	  "CN": "admin",
	  "hosts": [
	  ],
	  "key": {
		"algo": "rsa",
		"size": 2048
	  },
	  "names": [
		{
		  "C": "CN",
		  "ST": "BeiJing",
		  "L": "BeiJing",
		  "O": "system:masters",
		  "OU": "System"
		}
	  ]
	}
	EOF

	#签发证书
	cd $cert_path &&\
	cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes admin-csr.json | cfssljson -bare admin

	mv admin* $cert_path/kubectl_cert


	#########################################
	#**kube-controller-manager**证书


	[ -e $cert_path/kube-controller-manager_cert ] || mkdir -p $cert_path/kube-controller-manager_cert

	cat > $cert_path/kube-controller-manager-csr.json <<-EOF
	{
	  "CN": "system:kube-controller-manager",
	  "hosts": [
		"127.0.0.1",
		${tmp_ips}
	  ],
	  "key": {
		"algo": "rsa",
		"size": 2048
	  },
	  "names": [
		{
		  "C": "CN",
		  "ST": "BeiJing",
		  "L": "BeiJing",
		  "O": "system:kube-controller-manager",
		  "OU": "System"
		}
	  ]
	}
	EOF
	#签发证书
	cd $cert_path &&\
	cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-controller-manager-csr.json | cfssljson -bare kube-controller-manager

	mv kube-controller-manager* $cert_path/kube-controller-manager_cert



	########################################
	#签发kube-scheduler

	[ -e $cert_path/kube-scheduler_cert ] || mkdir -p $cert_path/kube-scheduler_cert

	 cat > $cert_path/kube-scheduler-csr.json <<-EOF
	 {
	  "CN": "system:kube-scheduler",
	  "hosts": [
		"127.0.0.1",
		${tmp_ips}
	  ],
	  "key": {
		"algo": "rsa",
		"size": 2048
	  },
	  "names": [
		{
		  "C": "CN",
		  "ST": "BeiJing",
		  "L": "BeiJing",
		  "O": "system:kube-scheduler",
		  "OU": "System"
		}
	  ]
	}
	EOF

	#生成证书
	cd ${cert_path} &&\
	cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-scheduler-csr.json | cfssljson -bare kube-scheduler

	mv kube-scheduler* $cert_path/kube-scheduler_cert
	
	
	
	
	
	#签发kube-proxy的证书文件
	[ -e $cert_path/kube-proxy_cert ] || mkdir -p $cert_path/kube-proxy_cert
	
	#获取所有节点ip
	tmp_ips=''
	for i in $(seq 0 `awk "BEGIN{print("${#NODE_IPS[@]}"-1)}"`);do

		if [ ${NODE_IPS[$i]} == ${NODE_IPS[-1]} ];then
			tmp_ips+=\"${NODE_IPS[$i]}\"
		else
			tmp_ips+=\"${NODE_IPS[$i]}\",
		fi
	done
	
	
	
	cat > $cert_path/kube-proxy-csr.json <<-EOF
{
  "CN": "system:kube-proxy",
  "hosts": [
    "127.0.0.1",
	${tmp_ips}
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "system:kube-proxy",
      "OU": "System"
    }
  ]
}
EOF

	#生成证书文件
	cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-proxy-csr.json | cfssljson -bare kube-proxy
	mv kube-proxy* $cert_path/kube-proxy_cert

	
	#签发kubelet证书文件
	
	[ -e $cert_path/kubelet_cert ] || mkdir -p $cert_path/kubelet_cert
	cat > $cert_path/kubelet-csr.json <<-EOF

{
  "CN": "system:kubelet",
  "hosts": [
    "127.0.0.1",
	${tmp_ips}
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "system:kubelet",
      "OU": "System"
    }
  ]
}
EOF

	cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kubelet-csr.json | cfssljson -bare kubelet
	mv kubelet* $cert_path/kubelet_cert
	
	
}


##########################################################

#部署etcd节点
install_etcd(){
	for ip in ${ETCD_IPS[@]};do

	#判断是否存在相关目录
	ssh $ip "[ -e $K8S_DIR/etcd ] || mkdir -p $K8S_DIR/etcd"
	ssh $ip "[ -e $K8S_CONF_DIR/cert ] || mkdir -p $K8S_CONF_DIR/cert"
	ssh $ip "[ -e $K8S_CONF_DIR/etcd/cert ] || mkdir -p $K8S_CONF_DIR/etcd/cert"
	ssh $ip "[ -e ${ETCD_DATA_DIR} ] || mkdir -p ${ETCD_DATA_DIR}"
	ssh $ip "[ -e /usr/local/etcd ] && rm -rf /usr/local/etcd"
	
	#分发文件
	cd $tmp_path &&\
	scp -r etcd-v3.5.2-linux-amd64.tar.gz $ip:/tmp
	if [ $? -eq 0 ];then
		ssh $ip "cd /tmp && tar -xf etcd-v3.5.2-linux-amd64.tar.gz"
		ssh $ip "cp -r /tmp/etcd-v3.5.2-linux-amd64 /usr/local/etcd"
		ssh $ip "echo 'PATH=/usr/local/etcd:$PATH' >>/etc/profile && source /etc/profile"
	fi
	#获取当前节点hostname
	name=`cat /etc/hosts| grep ${ip} | awk 'NR==1{print $2}'`
	#分发配置文件以及启动文件到各个etcd节点
	ssh $ip "cat > $K8S_CONF_DIR/etcd/etcd.yaml <<EOF

name: ${name}
data-dir: ${ETCD_DATA_DIR}
listen-peer-urls: https://${ip}:2380
listen-client-urls: https://${ip}:2379,https://127.0.0.1:2379
advertise-client-urls: https://${ip}:2379,https://127.0.0.1:2379
initial-advertise-peer-urls: https://${ip}:2380

initial-cluster: ${ETCD_NODES}
initial-cluster-token: etcd-cluster-token
initial-cluster-state: new
client-transport-security:
    cert-file: $K8S_CONF_DIR/etcd/cert/etcd.pem
    key-file: $K8S_CONF_DIR/etcd/cert/etcd-key.pem
    client-cert-auth: true
    trusted-ca-file: $K8S_CONF_DIR/cert/ca.pem
peer-transport-security:
    cert-file: $K8S_CONF_DIR/etcd/cert/etcd.pem
    key-file: $K8S_CONF_DIR/etcd/cert/etcd-key.pem
    client-cert-auth: true
    trusted-ca-file: $K8S_CONF_DIR/cert/ca.pem
EOF
"


	#配置systemd文件
	ssh $ip "cat > /usr/lib/systemd/system/etcd.service <<EOF

[Unit] 
Description=Etcd Server
After=network.target 
After=network-online.target 
Wants=network-online.target 
[Service] 
Type=notify 
WorkingDirectory=${ETCD_DATA_DIR} 
ExecStart=/usr/local/etcd/etcd --config-file=$K8S_CONF_DIR/etcd/etcd.yaml 
Restart=on-failure 
RestartSec=5 
LimitNOFILE=65536 
[Install] 
WantedBy=multi-user.target 
EOF
"	

	#分发证书文件
	scp	-r $cert_path/etcd_cert/* $ip:$K8S_CONF_DIR/etcd/cert
	scp -r  $cert_path/ca* $ip:$K8S_CONF_DIR/cert/


	done

	#启动etcd集群

	for ip in ${ETCD_IPS[@]};do
		{
		ssh $ip "systemctl daemon-reload && systemctl enable etcd && systemctl start etcd"
		} &
		#判断服务是否成功
		#ssh $ip "result=`systemctl is-active etcd`&& [ $result == 'active' ]"
	done
	wait

}
	
#部署kubernetes

install_apiserver(){

	cd $tmp_path &&\
	[ -e kubernetes-server-linux-amd64.tar.gz ] || (echo "apiserver 下载失败，请重新下载" && exit)
	tar -xf kubernetes-server-linux-amd64.tar.gz



#配置nginx
	cd $tmp_path &&\
	[ -e nginx_1.20.tar.gz ] || (echo "nginx is not exist" && exit)
	tar -xf nginx_1.20.tar.gz 
#构造nginx配置文件
	cat nginx_1.20/conf/nginx.conf<<EOF
worker_processes 1;
events {
    worker_connections  1024;
}
stream {
    upstream backend {
        hash  consistent;
		###
    }
    server {
        listen *:${KUBE_APISERVER_PORT};
        proxy_connect_timeout 1s;
        proxy_pass backend;
    }
}
EOF

	for ip in ${MASTER_IPS[@]};do
		sed -ri "/###/a\\\tserver ${ip}:6443        max_fails=3 fail_timeout=30s;"  nginx_1.20/conf/nginx.conf
	done





for ip in ${MASTER_IPS[@]};do

	#判断是否存在相关目录
	ssh $ip "[ -e $K8S_DIR ] || mkdir -p $K8S_DIR"
	ssh $ip "[ -e $K8S_CONF_DIR/cert ] || mkdir -p $K8S_CONF_DIR/cert"
	ssh $ip "[ -e /usr/local/kubernetes ] || mkdir -p /usr/local/kubernetes"
	ssh $ip "[ -e /var/log/kubernetes ] || mkdir -p /var/log/kubernetes"

	#分发软件
	cd $tmp_path &&\
	scp -r kubernetes/server/bin/kube-apiserver $ip:/usr/local/kubernetes/kube-apiserver
	scp -r kubernetes/server/bin/kubectl $ip:/usr/local/kubernetes/kubectl
	#scp -r kubernetes/server/bin/kubelet $ip:/usr/local/kubernetes/kubelet
	#scp -r kubernetes/server/bin/kube-scheduler $ip:/usr/local/kubernetes/kube-scheduler
	#scp -r kubernetes/server/bin/kube-proxy $ip:/usr/local/kubernetes/kube-proxy
	#scp -r kubernetes/server/bin/kube-controller-manager $ip:/usr/local/kubernetes/kube-controller-manager
	ssh $ip "echo 'PATH=/usr/local/kubernetes/:\$PATH' >>/etc/profile"
	ssh $ip "source /etc/profile"
	
	#分发证书和token
	scp -r $cert_path/kubernetes_cert/* $ip:$K8S_CONF_DIR/cert
	scp -r  $cert_path/ca* $ip:$K8S_CONF_DIR/cert/
	
	
	#生成配置文件
	ssh $ip "cat > /usr/lib/systemd/system/kube-apiserver.service <<EOF
[Unit] 
Description=Kubernetes API Server 
Documentation=https://github.com/kubernetes/kubernetes 
After=etcd.service 
Wants=etcd.service 
[Service] 
ExecStart=/usr/local/kubernetes/kube-apiserver \\
  --enable-admission-plugins=NamespaceLifecycle,NodeRestriction,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota \\
  --anonymous-auth=false \\
  --bind-address=${ip} \\
  --secure-port=6443 \\
  --advertise-address=${ip} \\
  --insecure-port=0 \\
  --authorization-mode=Node,RBAC \\
  --runtime-config=api/all=true \\
  --enable-bootstrap-token-auth \\
  --service-cluster-ip-range=${SERVICE_CIDR} \\
  --token-auth-file=$K8S_CONF_DIR/cert/token.csv \\
  --service-node-port-range=30000-50000 \\
  --tls-cert-file=$K8S_CONF_DIR/cert/kube-apiserver.pem \\
  --tls-private-key-file=$K8S_CONF_DIR/cert/kube-apiserver-key.pem \\
  --client-ca-file=$K8S_CONF_DIR/cert/ca.pem \\
  --kubelet-client-certificate=$K8S_CONF_DIR/cert/kube-apiserver.pem \\
  --kubelet-client-key=$K8S_CONF_DIR/cert/kube-apiserver-key.pem \\
  --service-account-key-file=$K8S_CONF_DIR/cert/ca-key.pem \\
  --service-account-signing-key-file=$K8S_CONF_DIR/cert/ca-key.pem \\
  --service-account-issuer=api \\
  --etcd-cafile=$K8S_CONF_DIR/cert/ca.pem \\
  --etcd-certfile=$K8S_CONF_DIR/etcd/cert/etcd.pem \\
  --etcd-keyfile=$K8S_CONF_DIR/etcd/cert/etcd-key.pem \\
  --etcd-servers=${ETCD_ENDPOINTS} \\
  --enable-swagger-ui=true \\
  --allow-privileged=true \\
  --apiserver-count=3 \\
  --audit-log-maxage=30 \\
  --audit-log-maxbackup=3 \\
  --audit-log-maxsize=100 \\
  --audit-log-path=/var/log/kube-apiserver-audit.log \\
  --event-ttl=1h \\
  --alsologtostderr=true \\
  --logtostderr=false \\
  --log-dir=/var/log/kubernetes \\
  --requestheader-client-ca-file=$K8S_CONF_DIR/cert/ca.pem \\
  --requestheader-allowed-names=front-proxy-client \\
  --requestheader-extra-headers-prefix='X-Remote-Extra-'\\
  --requestheader-group-headers=X-Remote-Group \\
  --requestheader-username-headers=X-Remote-User\\
  --proxy-client-cert-file=$K8S_CONF_DIR/cert/ca.pem \\
  --proxy-client-key-file=$K8S_CONF_DIR/cert/ca-key.pem
  --v=4 
Restart=on-failure 
RestartSec=5 
Type=notify 
LimitNOFILE=65536 
[Install]
WantedBy=multi-user.target
EOF
"
	#启动服务
	ssh $ip "systemctl daemon-reload && systemctl enable kube-apiserver.service && systemctl start kube-apiserver.service"


if [ ${#MASTER_IPS[@]} -gt 1 ];then
	
	#分发nginx配置
	cd $tmp_path &&\
	scp -r nginx_1.20 $ip:/usr/local/nginx_1.20
	#分发nginx启动配置文件
	ssh $ip "cat > /usr/lib/systemd/system/kube-nginx.service  <<EOF
[Unit]
Description=kube-apiserver nginx proxy
After=network.target
After=network-online.target
Wants=network-online.target
[Service]
Type=forking
ExecStartPre=/usr/local/nginx_1.20/sbin/nginx -c /usr/local/nginx_1.20/conf/nginx.conf -p /usr/local/nginx_1.20 -t
ExecStart=/usr/local/nginx_1.20/sbin/nginx -c /usr/local/nginx_1.20/conf/nginx.conf -p /usr/local/nginx_1.20
ExecReload=/usr/local/nginx_1.20/sbin/nginx -c /usr/local/nginx_1.20/conf/nginx.conf -p /usr/local/nginx_1.20 -s reload
PrivateTmp=true
Restart=always
RestartSec=5
StartLimitInterval=0
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
"
	#启动nginx
	ssh $ip "systemctl daemon-reload && systemctl enable kube-nginx && systemctl start kube-nginx "

	
	
	
	
	
	#安装keepalived
	#which keepalived &> /dev/null	
	#[ $? -eq 0 ] || yum install -y keepalived 
	ssh $ip "yum install -y keepalived"
	
	#判断是否是指定的vip节点
	if [ "$KEEPALIVED_VIP" == "$ip" ];then
		ret='MASTER'
	else
		ret='BACKUP'
	fi
	
	
	#分发keepalived 配置文件
	ssh $ip "cat > /etc/keepalived/keepalived.conf <<EOF
! Configuration File for keepalived
global_defs {
   router_id ${ip}  
}
vrrp_script chk_nginx {
    script '/etc/keepalived/check_port.sh ${KUBE_APISERVER_PORT}'  
    interval 2
    weight -20
}
vrrp_instance VI_1 { 
    state ${ret}   
    interface ${IFACE} 
    virtual_router_id 251  
    priority 100  
    advert_int 1  
    mcast_src_ip ${ip}
    nopreempt
    authentication {  
        auth_type PASS
        auth_pass 11111111
    }
    track_script {
         chk_nginx
    }
    virtual_ipaddress {
        ${KUBE_APISERVER} 
    }
}
EOF
"	
	#分发检测脚本
	scp -r $tmp_path/check_port.sh $ip:/etc/keepalived/check_port.sh
	#脚本赋权
	ssh $ip "chmod a+x /etc/keepalived/check_port.sh"
	#启动nginx以及keeplived
	ssh $ip "systemctl daemon-reload && systemctl enable keepalived && systemctl start keepalived "
		
fi	

done
}


#部署kubectl
install_kubectl(){
	cd $tmp_path &&\
	[ -d /usr/local/kubernetes/ ] || mkdir -p /usr/local/kubernetes/
	cp -r kubernetes/server/bin/kubectl /usr/local/kubernetes/kubectl
	[ -e ~/.kube ] || mkdir -p ~/.kube
	echo 'export PATH=$PATH:/usr/local/kubernetes/' >> /etc/profile
	source /etc/profile		
	
	
	cd $cert_path/kubectl_cert/ &&\
	kubectl config set-cluster kubernetes --certificate-authority=$cert_path/ca.pem --embed-certs=true --server=https://${KUBE_APISERVER}:${KUBE_APISERVER_PORT} --kubeconfig=kube.config
	
	kubectl config set-credentials admin --client-certificate=admin.pem --client-key=admin-key.pem --embed-certs=true --kubeconfig=kube.config
	
	kubectl config set-context kubernetes --cluster=kubernetes --user=admin --kubeconfig=kube.config
	
	kubectl config use-context kubernetes --kubeconfig=kube.config
	cp -r kube.config ~/.kube/config
	
	kubectl create clusterrolebinding kube-apiserver:kubelet-apis --clusterrole=system:kubelet-api-admin --user kubernetes
	
	for ip in ${MASTER_IPS[@]};do

		#master节点部署kubectl
		ssh $ip "[ -d /usr/local/kubernetes/ ] || mkdir -p /usr/local/kubernetes/"
		cd $tmp_path &&\
		scp -r kubernetes/server/bin/kubectl $ip:/usr/local/kubernetes/kubectl
		#分发证书到master节点，方便签发证书
		ssh $ip "[ -e $K8S_CONF_DIR/kubectl/kubectl_cert ] || mkdir -p $K8S_CONF_DIR/kubectl/kubectl_cert" 
		
		scp -r $cert_path/kubectl_cert/* $ip:$K8S_CONF_DIR/kubectl/kubectl_cert/
		

		ssh $ip "[ -e ~/.kube ] || mkdir -p ~/.kube"
		scp -r $cert_path/kubectl_cert/kube.config $ip:~/.kube/config
		ssh $ip "echo 'export PATH=\$PATH:/usr/local/kubernetes/' >> /etc/profile"
		ssh $ip "source /etc/profile"
		#ssh $ip " echo 'source <(kubectl completion bash)' >>~/.bashrc"
	done

}

#部署**kube-controller-manager**

install_kube-controller-manager(){

	#创建配置文件
	cd $cert_path/kube-controller-manager_cert/ &&\
	kubectl config set-cluster kubernetes --certificate-authority=$cert_path/ca.pem --embed-certs=true --server=https://${KUBE_APISERVER}:${KUBE_APISERVER_PORT} --kubeconfig=kube-controller-manager.kubeconfig

	#设置客户端认证参数
	kubectl config set-credentials system:kube-controller-manager --client-certificate=kube-controller-manager.pem --client-key=kube-controller-manager-key.pem --embed-certs=true --kubeconfig=kube-controller-manager.kubeconfig

	#设置上下文
	 kubectl config set-context system:kube-controller-manager --cluster=kubernetes --user=system:kube-controller-manager --kubeconfig=kube-controller-manager.kubeconfig
	 
	#切换上下文
	 kubectl config use-context system:kube-controller-manager --kubeconfig=kube-controller-manager.kubeconfig 




for ip in ${MASTER_IPS[@]};do
	ssh $ip "[ -d /usr/local/kubernetes/ ] || mkdir -p /usr/local/kubernetes/"
	cd $tmp_path &&\
	scp -r kubernetes/server/bin/kube-controller-manager $ip:/usr/local/kubernetes/kube-controller-manager

	#分发配置文件
	cd $cert_path/kube-controller-manager_cert/ &&\
	ssh $ip "[ -e $K8S_CONF_DIR/kube-controller-manager ] || mkdir -p $K8S_CONF_DIR/kube-controller-manager"
	ssh $ip "[ -e $K8S_CONF_DIR/kube-controller-manager/cert ] || mkdir -p $K8S_CONF_DIR/kube-controller-manager/cert"
	scp -r kube-controller-manager.kubeconfig $ip:$K8S_CONF_DIR/kube-controller-manager/kube-controller-manager.kubeconfig
	scp -r kube-controller-manager* $ip:$K8S_CONF_DIR/kube-controller-manager/cert/
	
	
	#分发启动文件
	ssh $ip "cat > /usr/lib/systemd/system/kube-controller-manager.service <<-EOF
[Unit] 
Description=Kubernetes Controller Manager 
Documentation=https://github.com/kubernetes/kubernetes 
[Service] 
ExecStart=/usr/local/kubernetes/kube-controller-manager \\
 --secure-port=10257 \\
 --bind-address=127.0.0.1 \\
 --kubeconfig=${K8S_CONF_DIR}/kube-controller-manager/kube-controller-manager.kubeconfig \\
 --service-cluster-ip-range=${SERVICE_CIDR}\\
 --cluster-name=kubernetes\\
 --cluster-signing-cert-file=${K8S_CONF_DIR}/cert/ca.pem\\
 --cluster-signing-key-file=${K8S_CONF_DIR}/cert/ca-key.pem\\
 --allocate-node-cidrs=true\\
 --cluster-cidr=${CLUSTER_CIDR} --experimental-cluster-signing-duration=87600h\\
 --root-ca-file=${K8S_CONF_DIR}/cert/ca.pem \\
 --service-account-private-key-file=${K8S_CONF_DIR}/cert/ca-key.pem \\
 --leader-elect=true \\
 --feature-gates=RotateKubeletServerCertificate=true \\
 --controllers=*,bootstrapsigner,tokencleaner \\
 --horizontal-pod-autoscaler-sync-period=10s \\
 --tls-cert-file=${K8S_CONF_DIR}/kube-controller-manager/cert/kube-controller-manager.pem \\
 --tls-private-key-file=${K8S_CONF_DIR}/kube-controller-manager/cert/kube-controller-manager-key.pem \\
 --use-service-account-credentials=true \\
 --alsologtostderr=true \\
 --logtostderr=false \\
 --log-dir=/var/log/kubernetes \\
 --v=2 
Restart=on-failure 
RestartSec=5 
[Install] 
WantedBy=multi-user.target 

EOF
"
	#启动服务
	ssh $ip "systemctl daemon-reload  && systemctl enable kube-controller-manager.service && systemctl start kube-controller-manager.service "

done	
}


#部署**kube-scheduler**
install_kube-scheduler(){

	cd $cert_path/kube-scheduler_cert &&\
	kubectl config set-cluster kubernetes --certificate-authority=$cert_path/ca.pem --embed-certs=true --server=https://${KUBE_APISERVER}:${KUBE_APISERVER_PORT} --kubeconfig=kube-scheduler.kubeconfig 

	#设置集群认证信息
	kubectl config set-credentials system:kube-scheduler --client-certificate=kube-scheduler.pem --client-key=kube-scheduler-key.pem --embed-certs=true --kubeconfig=kube-scheduler.kubeconfig 

	#设置上下文
	kubectl config set-context system:kube-scheduler --cluster=kubernetes --user=system:kube-scheduler --kubeconfig=kube-scheduler.kubeconfig 

	#切换上下文
	kubectl config use-context system:kube-scheduler --kubeconfig=kube-scheduler.kubeconfig



for ip in ${MASTER_IPS[@]};do
	ssh $ip "[ -d /usr/local/kubernetes/ ] || mkdir -p /usr/local/kubernetes/"
	cd $tmp_path &&\
	scp -r kubernetes/server/bin/kube-scheduler $ip:/usr/local/kubernetes/kube-scheduler
		
	#分发config配置文件
	ssh $ip "[ -e $K8S_CONF_DIR/kube-scheduler ] || mkdir -p $K8S_CONF_DIR/kube-scheduler" 
	cd $cert_path/kube-scheduler_cert &&\
	scp -r kube-scheduler.kubeconfig $ip:$K8S_CONF_DIR/kube-scheduler/kube-scheduler.kubeconfig
	
	
	#创建启动配置文件
	ssh $ip "cat > /usr/lib/systemd/system/kube-scheduler.service <<EOF
[Unit] 
Description=Kubernetes Scheduler 
Documentation=https://github.com/kubernetes/kubernetes 
[Service] 
ExecStart=/usr/local/kubernetes/kube-scheduler \\
 --address=127.0.0.1 \\
 --kubeconfig=${K8S_CONF_DIR}/kube-scheduler/kube-scheduler.kubeconfig \\
 --leader-elect=true \\
 --alsologtostderr=true \\
 --logtostderr=false \\
 --log-dir=/var/log/kubernetes \\
 --v=2 
Restart=on-failure 
RestartSec=5 
[Install] 
WantedBy=multi-user.target 
EOF
"	
	#启动服务
	ssh $ip "systemctl daemon-reload && systemctl enable kube-scheduler.service && systemctl start kube-scheduler.service"

done

}


#部署kube-proxy
install_kube-proxy(){

	#设置apiserver信息
	cd $cert_path/kube-proxy_cert &&\
	kubectl config set-cluster kubernetes --certificate-authority=$cert_path/ca.pem --embed-certs=true --server=https://${KUBE_APISERVER}:${KUBE_APISERVER_PORT} --kubeconfig=kube-proxy.kubeconfig

	#设置集群认证信息
	kubectl config set-credentials kube-proxy --client-certificate=kube-proxy.pem --client-key=kube-proxy-key.pem --embed-certs=true --kubeconfig=kube-proxy.kubeconfig

	#设置上下文
	kubectl config set-context default --cluster=kubernetes --user=kube-proxy --kubeconfig=kube-proxy.kubeconfig

	#切换上下文
	kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig




for ip in ${NODE_IPS[@]};do

	ssh $ip "[ -d /usr/local/kubernetes/ ] || mkdir -p /usr/local/kubernetes/"
	cd $tmp_path &&\
	scp -r kubernetes/server/bin/kube-proxy $ip:/usr/local/kubernetes/kube-proxy
	
	#分发kubeconfig文件
	ssh $ip "[ -e $K8S_CONF_DIR/kube-proxy ] || mkdir -p $K8S_CONF_DIR/kube-proxy"
	cd $cert_path/kube-proxy_cert &&\
	scp -r kube-proxy.kubeconfig $ip:$K8S_CONF_DIR/kube-proxy/kube-proxy.kubeconfig
	
	#获取当前节点hostname
	name=`cat /etc/hosts| grep ${ip} | awk 'NR==1{print $2}'`
	#创建启动文件
		
	ssh $ip "cat >$K8S_CONF_DIR/kube-proxy/kube-proxy.yaml<<EOF
kind: KubeProxyConfiguration 
apiVersion: kubeproxy.config.k8s.io/v1alpha1 
bindAddress: 0.0.0.0 
clientConnection: 
  kubeconfig: '${K8S_CONF_DIR}/kube-proxy/kube-proxy.kubeconfig' 
clusterCIDR: '${CLUSTER_CIDR}'  
conntrack: 
  maxPerCore: 32768 
  min: 131072 
  tcpCloseWaitTimeout: 1h0m0s 
  tcpEstablishedTimeout: 24h0m0s 
healthzBindAddress: 0.0.0.0:10256 
hostnameOverride: '${name}' 
metricsBindAddress: 0.0.0.0:10249 
mode: 'ipvs'
EOF
"

	#配置systemd启动文件
	ssh $ip "cat > /usr/lib/systemd/system/kube-proxy.service <<EOF

[Unit] 
Description=Kubernetes Kube-Proxy Server 
Documentation=https://github.com/kubernetes/kubernetes 
After=network.target 
[Service] 
ExecStart=/usr/local/kubernetes/kube-proxy --config=$K8S_CONF_DIR/kube-proxy/kube-proxy.yaml 
Restart=always 
RestartSec=5 
LimitNOFILE=65536 
[Install] 
WantedBy=multi-user.target
EOF
"
	
	#启动服务
	ssh $ip "systemctl daemon-reload && systemctl enable kube-proxy.service && systemctl start kube-proxy.service"
 
	
done



}


#部署Containerd

install_containerd(){

		for ip in ${NODE_IPS[@]};do
			cd $tmp_path &&\
			scp -r cri-containerd-cni-1.6.1-linux-amd64.tar.gz $ip:/tmp
			ssh $ip "tar --no-overwrite-dir -xf /tmp/cri-containerd-cni-1.6.1-linux-amd64.tar.gz -C /"
		
			#生成配置文件
			#创建配置文件存放目录，所有节点
			ssh $ip "[ -e /etc/containerd ] || mkdir -p /etc/containerd"

			#生成默认配置文件，任意节点

			ssh $ip "containerd config default >/etc/containerd/config.toml"

			#修改配置文件，只需要修改两次即可
			#1.使用 systemd cgroup 驱动程序
			ssh $ip "sed -i 's@SystemdCgroup = false@SystemdCgroup = true@' /etc/containerd/config.toml"
				
			#2.修改根基础镜像pause的容器地址
			ssh $ip "sed -i 's@k8s.gcr.io/pause:3.6@registry.aliyuncs.com/google_containers/pause:3.6@' /etc/containerd/config.toml"
			
			#启动服务
			ssh $ip "systemctl daemon-reload && systemctl enable containerd && systemctl start containerd"
			
			#分发runc
			chmod a+x runc.amd64 
			scp -r runc.amd64 $ip:/usr/local/sbin/runc
			
	
		done

}


#部署kubelet
install_kubelet(){

		#创建kubelet.kubeconfig
		# 设置集群参数 
		cd $cert_path/kubelet_cert &&\
		kubectl config set-cluster kubernetes --certificate-authority=$cert_path/ca.pem --embed-certs=true --server=https://${KUBE_APISERVER}:${KUBE_APISERVER_PORT} --kubeconfig=kubelet.kubeconfig 

		# 设置客户端认证参数 
		kubectl config set-credentials system:kubelet --client-certificate=kubelet.pem --embed-certs=true --client-key=kubelet-key.pem --kubeconfig=kubelet.kubeconfig 

		# 设置上下文参数 
		kubectl config set-context default --cluster=kubernetes --user=system:kubelet --kubeconfig=kubelet.kubeconfig 

		# 选择默认上下文 
		kubectl config use-context default --kubeconfig=kubelet.kubeconfig


		#绑定集群规则
		kubectl create clusterrolebinding kubelet-bootstrap --clusterrole=system:node --user=system:kubelet
		
	for ip in ${NODE_IPS[@]};do
		ssh $ip "[ -d /usr/local/kubernetes/ ] || mkdir -p /usr/local/kubernetes/"
		cd $tmp_path &&\
		scp -r kubernetes/server/bin/kubelet $ip:/usr/local/kubernetes/kubelet
	
	
	
		#分发证书
		ssh $ip "[ -e $K8S_CONF_DIR/kubelet/cert ] || mkdir -p $K8S_CONF_DIR/kubelet/cert"
		cd $cert_path/kubelet_cert &&\
		scp -r kubelet* $ip:$K8S_CONF_DIR/kubelet/cert/
		scp -r kubelet.kubeconfig $ip:$K8S_CONF_DIR/kubelet/
		
		#创建配置文件
		ssh $ip "[ -e /var/lib/kubelet/ ] || mkdir -p /var/lib/kubelet/"
		ssh $ip "cat >/var/lib/kubelet/config.yaml <<-EOF
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1 
address: 0.0.0.0
authentication:
  anonymous:
    enabled: false 
  webhook:
    cacheTTL: 2m0s
    enabled: true
  x509:
    clientCAFile: $K8S_CONF_DIR/cert/ca.pem
authorization:
  mode: Webhook 
  webhook:
    cacheAuthorizedTTL: 5m0s 
    cacheUnauthorizedTTL: 30s
cgroupDriver: systemd
cgroupsPerQOS: true
clusterDomain: ${CLUSTER_DNS_DOMAIN}
clusterDNS:
- ${CLUSTER_DNS_SVC_IP}
configMapAndSecretChangeDetectionStrategy: Watch
containerLogMaxFiles: 3
containerLogMaxSize: 10Mi
enforceNodeAllocatable:
- pods
eventBurst: 10
eventRecordQPS: 5
evictionHard:
  imagefs.available: 15%
  memory.available: 300Mi
  nodefs.available: 10%
  nodefs.inodesFree: 5%
evictionPressureTransitionPeriod: 5m0s
failSwapOn: true
fileCheckFrequency: 40s
hairpinMode: hairpin-veth
healthzBindAddress: 0.0.0.0
healthzPort: 10248
httpCheckFrequency: 40s
imageGCHighThresholdPercent: 85
imageGCLowThresholdPercent: 80
imageMinimumGCAge: 2m0s
kubeAPIBurst: 100
kubeAPIQPS: 50
makeIPTablesUtilChains: true
maxOpenFiles: 1000000
maxPods: 1150
nodeLeaseDurationSeconds: 40
nodeStatusReportFrequency: 1m0s
nodeStatusUpdateFrequency: 10s
oomScoreAdj: -999
podPidsLimit: -1
port: 10250
#disablereadOnlyPort
readOnlyPort: 0
resolvConf: /etc/resolv.conf
runtimeRequestTimeout: 2m0s
serializeImagePulls: true
streamingConnectionIdleTimeout: 4h0m0s
syncFrequency: 1m0s
#tlsCertFile:$K8S_CONF_DIR/kubelet/cert/kubelet.pem
#tlsPrivateKeyFile:$K8S_CONF_DIR/kubelet/cert/kubelet-key.pem 
EOF
"
	#获取当前节点hostname
	name=`cat /etc/hosts| grep ${ip} | awk 'NR==1{print $2}'`	
	#创建启动文件
	ssh $ip "cat > /usr/lib/systemd/system/kubelet.service <<-EOF
[Unit] 
Description=Kubernetes Kubelet 
Documentation=https://github.com/GoogleCloudPlatform/kubernetes 
[Service] 
WorkingDirectory=/var/lib/kubelet 
ExecStart=/usr/local/kubernetes/kubelet \\
 --config=/var/lib/kubelet/config.yaml \\
 --cni-bin-dir=/opt/cni/bin \\
 --cni-conf-dir=/etc/cni/net.d \\
 --container-runtime=remote \\
 --container-runtime-endpoint=unix:///run/containerd/containerd.sock \\
 --hostname-override=${name} \\
 --image-pull-progress-deadline=5m \\
 --kubeconfig=$K8S_CONF_DIR/kubelet/kubelet.kubeconfig \\
 --network-plugin=cni \\
 --pod-infra-container-image=registry.aliyuncs.com/google_containers/pause:3.2 \\
 --root-dir=/etc/cni/net.d \\
 --v=2 
Restart=always 
RestartSec=5 
[Install] 
WantedBy=multi-user.target
EOF
"
		#启动服务
		ssh $ip "systemctl daemon-reload && systemctl enable kubelet.service && systemctl restart kubelet.service"
	
	
	
	
	
	done
}


#部署calico网络插件
install_calico(){
	cd $tmp_path &&\
	sed -ri "s#ipcidr#${CLUSTER_CIDR}#" calico.yaml  
	#wget https://projectcalico.docs.tigera.io/v3.22/manifests/calico.yaml &> /dev/null
	#[ $? -ne 0 ] && echo "download calico.yaml fail..." && exit
	
	kubectl apply -f calico.yaml
	#kubectl apply -f $tmp_path/calico_other.yaml
}

#部署creDNS
install_coreDNS(){
	cd $tmp_path/ &&\
	sed -ri "s/10.254.0.2/${CLUSTER_DNS_SVC_IP}/" coreDNS.yaml
	kubectl apply -f coreDNS.yaml
	#tar -xf deployment-master.tar.gz &&\	
	#cd $tmp_path/deployment-master/kubernetes  &&\
	#./deploy.sh -i ${CLUSTER_DNS_SVC_IP} |kubectl apply -f -
	

}

#部署Dashboard
install_Dashboard(){
	cd $tmp_path &&\
	kubectl create -f rbac-dashboard.yaml
	kubectl create -f dashboard-k8s.yaml
	#部署metric-server
	kubectl apply -f metric-server.yaml &&\
	kubectl create clusterrolebinding kubernetes --clusterrole=cluster-admin --user=kubernetes
	#获取密码
	which jq &> /dev/null
	[ $? -eq 0 ] || yum install -y jq &> /dev/null
	token_name=`kubectl get secret -n kube-system | grep admin | awk '{print $1}'`
	kubectl get secret -n kube-system ${token_name} -o json | jq .data.token | awk -F '"' '{print $2}' | base64 -d > dashboard_token.txt

}



main(){
	init_os
	init_hosts
	download_soft
	install_cfssl
	init_ca_cert
	install_etcd
	install_apiserver
	install_kubectl
	install_kube-controller-manager
	install_kube-scheduler
	install_kube-proxy
	install_containerd
	install_kubelet
	install_calico
	sleep 120
	install_coreDNS
	sleep 120
	install_Dashboard
}
main





