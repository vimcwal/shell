#!/bin/bash
#备份此服务器的重要信息到备份服务器
#[ -f /etc/profile ] && . /etc/profile

name=`date +%F`


#并发数设置
count=3


#备份日志路径
message_success=/data5/backup/${name}/${name}_success.txt
message_fail=/data5/backup/${name}/${name}_fail.txt

#数据库相关
d_user=
d_passwd=
#备份路径
d_path=/data5/backup/${name}/mps
host=
port=3306


#添加并发,加快备份速度
fifofile=/tmp/$$.tmpfifo
mkfifo  $fifofile &&\
exec 5678<>$fifofile 
[ -n $fifofile ] && rm -rf $fifofile

for i in `seq $count`;
do
	echo >&5678
done





#检测是否存在相应的文件夹
[ -d ${b_path} ] || mkdir ${b_path} -p
[ -d ${d_path} ] || mkdir ${d_path} -p
[ -d ${d_path}/all ] || mkdir ${d_path}/all -p


#遍历数据库里面的库，排除部分系统表不进行备份
database=`mysql -u ${d_user} -p${d_passwd} -h ${host} -P ${port}  -e 'show databases' | grep -v "Database" | grep -v "information_schema" | grep -v "sys" | grep -v "performance_schema"`

#备份每个库里面的各个表，每个表备份成一个独立的sql文件
for i in ${database}
do
		[ -d ${d_path}/all/$i ] || mkdir /${d_path}/all/$i -p

	tables=`mysql -u ${d_user} -p${d_passwd} -h ${host} -P ${port} -e "use $i;show tables"`
	for k in ${tables[@]}
	do
		read -u 5678
		{
			if [ "$k" == "Tables_in_${i}" ];then
				:	
			else
				mysqldump -u ${d_user} -p${d_passwd} -h ${host} -P ${port} -R  --triggers --master-data=2 --single-transaction $i $k > ${d_path}/all/${i}/${i}_${k}.sql
			fi
			echo >&5678
		}&
	done
	

     	
done

wait
exec 5678<&-
#备份整库
#mysqldump -u ${d_user} -p${d_passwd} -R -E -B -h ${host} --master-data=2 --single-transaction --triggers -A >${d_path}/${name}_${db}.sql

#压缩备份
tar -czf ${d_path}/${name}.tar.gz ${d_path}/all &> /dev/null
size=`du -s ${d_path}/${name}.tar.gz  | awk '{print $1}'`

#写入日志信息
[ -f ${d_path}/${name}.tar.gz  -a  $size -gt 50000 ] && (echo "$name : backup is ok" >>${d_path}/success.txt && echo "$host $name success" >>$message_success)|| (echo "$name : backup fail......." >>${d_path}/error.txt && echo "$host $name fail" >>$message_fail)
[ -n ${d_path} ] && rm -rf ${d_path}/all/*

