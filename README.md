#define __KERNEL__
#define MODULE

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>

static struct nf_hook_ops myhook;  //用于注册我们函数的结构
 /*struct nf_hook_ops 
{ 
struct list_head list; 
nf_hookfn *hook; 
int pf; 
int hooknum; 
int priority; 
}; 
*/
//实现
unsigned int hook_func(unsigned int hooknum,struct sk_buff **skb,
const struct net_device *in,const struct net_device *out,
int (*okfn)(struct sk_buff *))

{
	struct sk_buff *myskb;

	myskb = *skb;
	struct tcphdr *tcp;
	struct icmphdr *icmp;
	struct udphdr *udp;	
	unsigned int *deny;
	
	if(myskb->nh.iph->protocol == 1) /*ICMP*/
	{
	printk("\nThis is an ICMP packet.\n");
	
	icmp=(struct icmphdr *)(myskb->data +(myskb->nh.iph->ihl*4));

	if(icmp->type == 8)
		{
			printk("This is a PING packet to be blocked from");
			unsigned char *f =(unsigned char *)&(myskb->nh.iph->saddr);

			printk(" %d,%d,%d,%d",*f,*(f+1),*(f+2),*(f+3));
			

			return NF_DROP;
		} 


	}


	if(myskb->nh.iph->protocol == 6)   /*TCP*/
	{
	printk("\nThis is a TCP packet.\n");
	
	tcp=(struct tcphdr *)(myskb->data + (myskb->nh.iph->ihl * 4));
	
	unsigned char *p =(unsigned char *)&(tcp->dest);

	printk("The dest port is %d.",((*p)*256)+*(p+1));

	unsigned char *deny_port = "\x00\x15";   /*port 21*/
	

	if ( (tcp->dest) == *(unsigned short *)deny_port)
	{
		unsigned char *f = (unsigned char *)&(myskb->nh.iph->saddr);
		printk("\nBlocked Port Number is %d, from %d.%d.%d.%d\n",*(deny_port +1 ),*f,*(f+1),*(f+2),*(f+3));
		
		
		
		return NF_DROP;
	}
	
	}

	if(myskb->nh.iph->protocol == 17)  /*UDP*/
	{
		printk("\nThis is an UDP packet.\n");
		udp=(struct udphdr *)(myskb->data + (myskb->nh.iph->ihl * 4));
	
	unsigned char *p =(unsigned char *)&(udp->dest);

	printk("The dest port is %d.",((*p)*256)+*(p+1));




	}	

return NF_ACCEPT;            //接收数据包



}
//初始化程序
int init_module()
{
	myhook.hook=hook_func;
	myhook.hooknum=NF_IP_LOCAL_IN;
	myhook.pf=PF_INET;
	myhook.priority=NF_IP_PRI_FIRST;

	nf_register_hook(&myhook);
	
	return 0;
}
//清楚程序
void cleanup_module()
{
	nf_unregister_hook(&myhook);

	printk("\nCleanUp\n");
}

MODULE_LICENSE("GPL");
