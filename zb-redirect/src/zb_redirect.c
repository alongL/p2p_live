#include 	<linux/init.h>
#include 	<linux/module.h>
#include 	<linux/netfilter.h>
#include 	<linux/socket.h>			/*PF_INET*/
#include 	<linux/netfilter_ipv4.h>	/*NF_IP_PRE_FIRST*/
#include 	<linux/skbuff.h>
#include 	<linux/netdevice.h>
#include 	<linux/inet.h> 				/*in_aton()*/
#include 	<net/ip.h>
#include 	<net/tcp.h>
#include 	<linux/netfilter_ipv4/ip_tables.h>
#include 	<linux/moduleparam.h>
#include	<linux/jiffies.h>			//jiffies get time


#define REDIRECT_HTTP_MAX_LEN 4096
#define MAX_HTTP_PATH_LEN 2048
char *g_localSrvUrl="http://192.168.1.1:8888";
char *g_brName="br-lan";

const char *http_302header = "HTTP/1.1 302 Found\r\n"
"Content-length: 0\r\n"
"Content-Type: text/html\r\n"
"Connection: close\r\n"
"Cache-control: no-cache\r\n"
"Location: %s%s&ori_host=%s\r\n"
"\r\n";

const char *http_302header_huya = "HTTP/1.1 302 Moved Temporarily\r\n"
"Access-Control-Allow-Origin: *\r\n"
"Accept: */*\r\n"
"Content-Type: text/html; charset=utf-8\r\n"
"Access-Control-Allow-Credentials: true\r\n"
"Content-length: 0\r\n"
"Location: %s%s&ori_host=%s\r\n"
"\r\n";

const char *http_302header_huya_app = "HTTP/1.0 302 Moved Temporarily\r\n"
"Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,video/x-mng,image/png,image/jpeg,image/gif;q=0.2,*/*;q=0.1\r\n"
"Access-Control-Allow-Credentials: true\r\n"
"Access-Control-Allow-Origin: \r\n*"
"Connection: keep-alive\r\n"
"Content-Length: 0\r\n"
"Content-Type: text/html; charset=utf-8\r\n"
"Location: %s%s&ori_host=%s\r\n"
"\r\n";

char g_httpContent[REDIRECT_HTTP_MAX_LEN]={0};
int g_httpLen=0;

int http_build_302_pkt(const char *path, const char *host)
{
    int len=-1;

    if (!path) {
        return -1;
    }
    //len = snprintf(g_httpContent, REDIRECT_HTTP_MAX_LEN, http_302header, g_localSrvUrl, path, host);
    len = snprintf(g_httpContent, REDIRECT_HTTP_MAX_LEN, http_302header_huya, g_localSrvUrl, path, host);
    //len = snprintf(g_httpContent, REDIRECT_HTTP_MAX_LEN, http_302header_huya_app, g_localSrvUrl, path, host);
    g_httpContent[REDIRECT_HTTP_MAX_LEN-1] = '\0';

    return len;
}

int skb_iphdr_init(struct sk_buff *skb, u8 protocol, u32 saddr, u32 daddr, int ip_len)
{
    struct iphdr *iph = NULL;

    // skb->data 移动到ip首部
    skb_push(skb, sizeof(struct iphdr));
    skb_reset_network_header(skb);
    iph = ip_hdr(skb);

    /* iph->version = 4; iph->ihl = 5; */
    iph->version  = 4;
    iph->ihl      = 5;
    iph->tos      = 0;
    iph->tot_len  = htons(ip_len);
    iph->id       = 0;
    iph->frag_off = htons(IP_DF);
    iph->ttl      = 64;
    iph->protocol = protocol;
    iph->check    = 0;
    iph->saddr    = saddr;
    iph->daddr    = daddr;
    iph->check    = ip_fast_csum(( unsigned char * )iph, iph->ihl);        

    return 0;
}

/*
 * 构建一个tcp数据包
 */
struct sk_buff* tcp_newpack(u32 saddr, u32 daddr, 
                            u16 sport, u16 dport,
                            u32 seq, u32 ack_seq,
                            u8 *msg, int len)
{
    struct sk_buff *skb = NULL;
    int total_len, eth_len, ip_len, header_len;
    int tcp_len;    
    struct tcphdr *th;
    struct iphdr *iph; 

    __wsum tcp_hdr_csum;

    // 设置各个协议数据长度
    tcp_len = len + sizeof( *th );
    ip_len = tcp_len + sizeof( *iph );
    eth_len = ip_len + ETH_HLEN;

    total_len = eth_len + NET_IP_ALIGN;
    total_len += LL_MAX_HEADER;
    header_len = total_len - len;

    // 分配skb
    skb = alloc_skb( total_len, GFP_ATOMIC );
    if ( !skb ) {
        printk("alloc_skb length %d failed./n", total_len );
        return NULL;
    }

    // 预先保留skb的协议首部长度大小
    skb_reserve( skb, header_len );

    skb_copy_to_linear_data( skb, msg, len );
    skb->len += len;

    // skb->data 移动到tdp首部
    skb_push( skb, sizeof( *th ) );
    skb_reset_transport_header( skb );
    th = tcp_hdr( skb );
    memset( th, 0x0, sizeof( *th ) );

    th->source  = sport;
    th->dest    = dport;    
    th->seq     = seq;
    th->ack_seq = ack_seq;
    th->urg_ptr = 0;
    th->doff    = 5;
    th->psh = 0x1;
    th->ack = 0x1;
    th->fin = 0x1;
    th->window = htons( 63857 );
    th->check    = 0;
    tcp_hdr_csum = csum_partial(th, tcp_len, 0);
    th->check = csum_tcpudp_magic(saddr, daddr, tcp_len, IPPROTO_TCP, tcp_hdr_csum );
    skb->csum=tcp_hdr_csum;                        
    if ( th->check == 0 )
    {
        th->check = CSUM_MANGLED_0;
    }

    skb_iphdr_init( skb, IPPROTO_TCP, saddr, daddr, ip_len );

    return skb;
}

/*
 * 根据来源ip,tcp端口发送tcp数据
 */
int _tcp_send_pack(struct sk_buff *skb,
                   struct iphdr *iph,
                   struct tcphdr *th)
{
    struct sk_buff *pskb = NULL;
    struct ethhdr *eth = NULL;
    //struct vlan_hdr *vhdr = NULL;
    struct net_device *outDev = NULL;
    int tcp_len = 0;
    u32 ack_seq = 0;
    int rc = -1;

    // 重新计算 Acknowledgement number
    tcp_len = ntohs(iph->tot_len) - ((iph->ihl + th->doff) << 2);
    ack_seq = ntohl(th->seq) + (tcp_len);
    ack_seq = htonl(ack_seq);

    pskb = tcp_newpack( iph->daddr, iph->saddr,
            th->dest, th->source, 
            th->ack_seq, ack_seq,
            g_httpContent, g_httpLen);


    if ( NULL == pskb )
    {
        goto _out;
    }

    // 复制VLAN 信息
#if 0
    if ( __constant_htons(ETH_P_8021Q) == skb->protocol ) 
    {
        vhdr = (struct vlan_hdr *)skb_push(pskb, VLAN_HLEN );
        vhdr->h_vlan_TCI = vlan_eth_hdr(skb)->h_vlan_TCI;
        vhdr->h_vlan_encapsulated_proto = __constant_htons(ETH_P_IP);
    }
#endif

    // skb->data 移动到eth首部
    eth = (struct ethhdr *) skb_push(pskb, ETH_HLEN);
    skb_reset_mac_header(pskb);
    pskb->protocol  = eth_hdr(skb)->h_proto;
    eth->h_proto    = eth_hdr(skb)->h_proto;
    memcpy(eth->h_source, eth_hdr(skb)->h_dest, ETH_ALEN);   
    memcpy(eth->h_dest, eth_hdr(skb)->h_source, ETH_ALEN);

    outDev = __dev_get_by_name(&init_net, g_brName);
    if (outDev)
    {
        pskb->dev = outDev;
        dev_queue_xmit(pskb);
        rc = 0;
    }
    else
    {
        kfree_skb(pskb);
    }

_out:   
    return rc;
}

int http_send_redirect(struct sk_buff *skb,
                       struct iphdr *iph,
                       struct tcphdr *th )
{
    int rc = -1;    

    rc = _tcp_send_pack(skb, iph, th);

    return rc;
}

static unsigned int zb_hook(unsigned int hook,
                            struct sk_buff *skb,
                            const struct net_device *in,
                            const struct net_device *out,
                            int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = NULL;
    struct ethhdr *eth = NULL;
    struct tcphdr *tcph = NULL;
    unsigned int sip = 0;
    unsigned int dip = 0;
    unsigned short sport=0, dport=0;
    unsigned char *payload=NULL;
    int contentLen=0;
    int i=0, found=0;
    char path[MAX_HTTP_PATH_LEN]={0};
    char host[1024]={0};

    if (!skb) {
        return NF_ACCEPT;
    }

    if (strcmp(skb->dev->name, g_brName) != 0) {
        return NF_ACCEPT;
    }

    if ((eth = eth_hdr(skb)) == NULL) {
        return NF_ACCEPT;
    }

    if (eth->h_proto != htons(ETH_P_IP)) {
        return NF_ACCEPT;
    }

    if ((iph = ip_hdr(skb)) == NULL) {
        return NF_ACCEPT;
    }

    if (iph->version != 4) {
        return NF_ACCEPT;
    }

    if (iph->protocol != 6) {
        return NF_ACCEPT;
    }

    sip = iph->saddr;
    dip = iph->daddr;
 
    tcph = (struct tcphdr *)((unsigned char *)iph+iph->ihl*4);
    sport = ntohs(tcph->source);
    dport = ntohs(tcph->dest);
    contentLen = ntohs(iph->tot_len) - iph->ihl*4 - tcph->doff*4;


    if (dport != 80) {
        return NF_ACCEPT;
    }

    payload = (unsigned char *)tcph + tcph->doff*4;   

    if (strncmp(payload, "GET ", 4) != 0) {
        return NF_ACCEPT;
    }

    payload += 4;
    contentLen -= 4;
    while(*payload != ' ' && i<contentLen) {
        path[i] = *payload++;
        i++;
    }

    if (i==contentLen) {
        return NF_ACCEPT;
    }
    path[i] = '\0';
    contentLen -= i;

    if (!strstr(path, ".flv?")) {
        return NF_ACCEPT;
    }

    i=0;
    while(i<contentLen && !found) {
        if(payload[i] == 'H' && payload[i+1] == 'o' && payload[i+2] == 's' && payload[i+3] == 't' &&
                    payload[i+4] == ':' && payload[i+5] == ' ') {
            found = 1;
            break;
        }
        i++;
    }

    if (found == 0) {
        return NF_ACCEPT;
    }

    payload += (i+6);
    contentLen -= (i+6);

    i=0;
    while(i<contentLen) {
        if (payload[i] == '\r' && payload[i+1] == '\n') {
            payload[i] = '\0';
            break;
        }
        host[i] = payload[i];
        i++;
    }

    if (i == contentLen) {
        return NF_ACCEPT;
    }
    
    printk("%s %d: find request: \r\nhost=%s, path=%s\r\n", __FUNCTION__, __LINE__, host, path);

    g_httpLen=http_build_302_pkt(path, host);
    http_send_redirect(skb, iph, tcph);  
    //tcph->ack = 0;
    //tcph->fin = 0;
    //tcph->rst = 0x1;

    return NF_DROP;
}


#define NF_IP_PRE_ROUTING   0
#define NF_IP_FORWARD       2

static struct nf_hook_ops zbho={
        .hook           = zb_hook,
        //.owner          = THIS_MODULE,
        .pf             = PF_INET,
        .hooknum        = NF_IP_FORWARD,
        .priority       = NF_IP_PRI_FIRST,
};

static int __init zbhook_init(void)	//__init,....gcc......init..section;
{
    int ret = 0;

    ret = nf_register_hook(&zbho);

    if(ret < 0)
    {
        printk("%s\n", "can't modify skb hook!");
        return ret;
    }

    return ret;
}

static void zbhook_fini(void)
{
    nf_unregister_hook(&zbho);
}

module_init(zbhook_init);
module_exit(zbhook_fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("james guan");
