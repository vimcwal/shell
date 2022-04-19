## shell
shell脚本集合

  # 备份mysql数据脚本
  - backup_mysql.sh  
  
  # centos初始化脚本
  - centos7初始化.sh
  
  # 获取mysql锁等待语句脚本、表库大小脚本
  - get_mysql_info


 # 基于二进制k8s进行安装，集群版本为 v1.23    
 # containerd + etcd + k8s 
   - 执行前需要初始化环境 
     wget -O - http://download.lsythink.online/dl/scripts/init_os.sh | bash
     #设置好初始化参数之后执行
   - bash auto-install-k8s.sh
