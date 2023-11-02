# coding: utf-8

from scapy.all import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from Alex_ui import *
import multiprocessing


class Alex_sniffer(Ui_MainWindow,QtWidgets.QMainWindow):
    filter = ""   #捕获过滤
    iface = ""   #网卡
    packetList = []
    q = multiprocessing.Queue()


    def __init(self):
        super(Alex_sniffer,self).__init__()


    def setupUi(self, MainWindow):
        super(Alex_sniffer, self).setupUi(MainWindow)
        self.tableWidget.insertColumn(7)
        self.tableWidget.setColumnHidden(7,True)#将最后一列隐藏
        self.tableWidget.horizontalHeader().setSectionsClickable(False) #可以禁止点击表头的列
        self.tableWidget.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows) #设置 不可选择单个单元格，只可选择一行。
        self.tableWidget.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers) #设置表格不可更改
        self.tableWidget.verticalHeader().setVisible(False) #去掉垂直表头
        self.tableWidget.setColumnWidth(0,60)
        self.tableWidget.setColumnWidth(2,150)
        self.tableWidget.setColumnWidth(3,150)
        self.tableWidget.setColumnWidth(4,60)
        self.tableWidget.setColumnWidth(5,60)
        self.tableWidget.setColumnWidth(6,600)
        self.treeWidget.setHeaderHidden(True) #去掉表头
        self.treeWidget.setColumnCount(1)


    #设置槽函数
    def setSlot(self):
        self.tableWidget.itemClicked.connect(self.clickInfo)  #左键点击
        global count
        count = 0
        global display
        display = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.statistics)
        #开启统计
        self.timer.start(1000)
        self.comboBoxIface = QComboBox()
        self.toolBar.addWidget(self.comboBoxIface)
        self.LookupIface()
        startAction = QAction(QIcon('./img/start.webp'),'&开始捕获(Ctrl+E)',self)
        startAction.setShortcut('Ctrl+E')
        startAction.triggered.connect(self.Start)
        self.toolBar.addAction(startAction)
        stopAction = QAction(QIcon('./img/stop.webp'),'&停止捕获(Ctrl+Q)',self)
        stopAction.setShortcut('Ctrl+Q')
        stopAction.triggered.connect(self.Stop)
        self.toolBar.addAction(stopAction)
        saveAction = QAction(QIcon('./img/save.webp'),'&保存(Ctrl+S)',self)
        saveAction.setShortcut('Ctrl+S')
        saveAction.triggered.connect(self.savePackets)
        self.toolBar.addAction(saveAction)


    #遍历网卡
    def LookupIface(self):
        eth_local=[]
        a = repr(conf.route).split('\n')[1:]
        for x in a:
            b = re.search(r'[a-zA-Z](.*)[a-zA-Z]',x)
            eth_local.append(b.group())
        #去重
        c = []
        c.append(eth_local[0])
        for i in range(0,len(eth_local),1):
            m = 0
            for j in range(0,len(c),1):
                if c[j] == eth_local[i]:
                    m += 1
            if m==0:
                c.append(eth_local[i])
        #添加到comboBoxIface中
        self.comboBoxIface.addItems(c)


    #开始捕获
    def Start(self):
        global count
        count = 0
        global display
        display = 0
        self.packetList = []
        self.startTime = time.time()
        self.iface = self.comboBoxIface.currentText()
        self.tableWidget.setRowCount(0)
        self.tableWidget.removeRow(0)
        self.SnifferThread = SnifferThread(self.filter,self.iface)
        self.SnifferThread.HandleSignal.connect(self.display)
        self.SnifferThread.start()


    #停止捕获
    def Stop(self):
        self.SnifferThread.terminate()


    #显示捕获的数据包
    def display(self,packet):
        global count
        global display
        packetTime = '{:.7f}'.format(packet.time - self.startTime)
        type = packet.type
        if type == 0x800 :
            count += 1
            display = count
            row = self.tableWidget.rowCount()
            self.tableWidget.insertRow(row)
            self.tableWidget.setItem(row,0, QtWidgets.QTableWidgetItem(str(count)))
            self.tableWidget.setItem(row,1,QtWidgets.QTableWidgetItem(str(packetTime)))
            self.tableWidget.setItem(row,2, QtWidgets.QTableWidgetItem(packet[IP].src))
            self.tableWidget.setItem(row,3, QtWidgets.QTableWidgetItem(packet[IP].dst))
            self.tableWidget.setItem(row,5, QtWidgets.QTableWidgetItem(str(len(packet))))
            self.tableWidget.setItem(row,7, QtWidgets.QTableWidgetItem(raw(packet).decode('Windows-1252','ignore')))
            #TCP
            if packet[IP].proto == 6:
                self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('TCP'))
                if packet.haslayer('TCP'):
                    flag = ''
                    if packet[TCP].flags.A:
                        if flag == '':
                            flag += 'ACK'
                        else:
                            flag += ',ACK'
                    if packet[TCP].flags.R:
                        if flag == '':
                            flag += 'RST'
                        else:
                            flag += ',RST'
                    if packet[TCP].flags.S:
                        if flag == '':
                            flag += 'SYN'
                        else:
                            flag += ',SYN'
                    if packet[TCP].flags.F:
                        if flag == '':
                            flag += 'FIN'
                        else:
                            flag += ',FIN'
                    if packet[TCP].flags.U:
                        if flag == '':
                            flag += 'URG'
                        else:
                            flag += ',URG'
                    if packet[TCP].flags.P:
                        if flag == '':
                            flag += 'PSH'
                        else:
                            flag += ',PSH'
                    if flag == '':
                        self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('%s -> %s Seq：%s Ack：%s Win：%s' % (packet[TCP].sport,packet[TCP].dport,packet[TCP].seq,packet[TCP].ack,packet[TCP].window)))
                    else:
                        self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('%s -> %s [%s] Seq：%s Ack：%s Win：%s' % (packet[TCP].sport,packet[TCP].dport,flag,packet[TCP].seq,packet[TCP].ack,packet[TCP].window)))
            #UDP
            elif packet[IP].proto == 17:
                self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('UDP'))
                self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('%s -> %s 长度(len)：%s' % (packet[UDP].sport,packet[UDP].dport,packet[UDP].len)))
            #ICMP
            elif packet[IP].proto == 1:
                self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('ICMP'))
                if packet.haslayer('ICMP'):
                    if packet[ICMP].type == 8:
                        self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('Echo (ping) request id：%s seq：%s' % (packet[ICMP].id,packet[ICMP].seq)))
                    elif packet[ICMP].type == 0:
                        self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('Echo (ping) reply id：%s seq：%s' % (packet[ICMP].id,packet[ICMP].seq)))
                    else:
                        self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('type：%s id：%s seq：%s' % (packet[ICMP].type,packet[ICMP].id,packet[ICMP].seq)))
            #IGMP
            elif packet[IP].proto == 2:
                self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('IGMP'))
                self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem(''))
            #其他协议
            else:
                self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem(str(packet[IP].proto)))
            #着色分析
            self.colorItem(row,packet)
            #加入packetList中
            self.packetList.append(packet)
        #ARP
        elif type == 0x806 :
            count += 1
            display = count
            row = self.tableWidget.rowCount()
            self.tableWidget.insertRow(row)
            self.tableWidget.setItem(row,0, QtWidgets.QTableWidgetItem(str(count)))
            self.tableWidget.setItem(row,1,QtWidgets.QTableWidgetItem(str(packetTime)))
            self.tableWidget.setItem(row,2, QtWidgets.QTableWidgetItem(packet[ARP].psrc))
            self.tableWidget.setItem(row,3, QtWidgets.QTableWidgetItem(packet[ARP].pdst))
            self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('ARP'))
            self.tableWidget.setItem(row,5, QtWidgets.QTableWidgetItem(str(len(packet))))
            if packet[ARP].op == 1:  #request
                self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('Who has %s? Tell %s' % (packet[ARP].pdst,packet[ARP].psrc)))
            elif packet[ARP].op == 2:  #reply
                self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('%s is at %s' % (packet[ARP].psrc,packet[ARP].hwsrc)))
            self.tableWidget.setItem(row,7, QtWidgets.QTableWidgetItem(raw(packet).decode('Windows-1252','ignore')))
            #着色分析
            self.colorItem(row,packet)
            #加入packetList中
            self.packetList.append(packet)


    #着色分析
    def colorItem(self,row,packet):
        type = packet.type
        #IP
        if type == 0x800 :
            #IP坏包
            if packet.haslayer('IP') == 0:
                for i in range(7):
                    self.tableWidget.item(row,i).setBackground(Qt.black)   #设置背景颜色
                    self.tableWidget.item(row,i).setForeground(Qt.red)     #设置字体颜色
            #TCP
            if packet[IP].proto == 6:
                #TCP坏包
                if packet.haslayer('TCP') == 0:
                    for i in range(7):
                        self.tableWidget.item(row,i).setBackground(Qt.black)   #设置背景颜色
                        self.tableWidget.item(row,i).setForeground(Qt.red)     #设置字体颜色
                #TCP SYN/FIN
                elif packet[TCP].flags.S or packet[TCP].flags.F:
                    for i in range(7):
                        self.tableWidget.item(row,i).setBackground(QColor('#646464'))   #设置背景颜色
                #TCP RST
                elif packet[TCP].flags.R:
                    for i in range(7):
                        self.tableWidget.item(row,i).setBackground(QColor('#990000'))   #设置背景颜色
                        self.tableWidget.item(row,i).setForeground(QColor('#FFCC33'))     #设置字体颜色
                else:
                    for i in range(7):
                        self.tableWidget.item(row,i).setBackground(QColor('#DDDDDD'))   #设置背景颜色
            #UDP
            elif packet[IP].proto == 17:
                #UDP坏包
                if packet.haslayer('UDP') == 0:
                    for i in range(7):
                        self.tableWidget.item(row,i).setBackground(Qt.black)   #设置背景颜色
                        self.tableWidget.item(row,i).setForeground(Qt.red)     #设置字体颜色
                else:
                    for i in range(7):
                        self.tableWidget.item(row,i).setBackground(QColor('#CCFFFF'))   #设置背景颜色
            #ICMP
            elif packet[IP].proto == 1:
                #ICMP坏包
                if packet.haslayer('ICMP') == 0:
                    for i in range(7):
                        self.tableWidget.item(row,i).setBackground(Qt.black)   #设置背景颜色
                        self.tableWidget.item(row,i).setForeground(Qt.red)     #设置字体颜色
                #ICMP errors
                elif packet[ICMP].type == 3 or packet[ICMP].type == 4 or packet[ICMP].type == 5 or packet[ICMP].type == 11:
                    for i in range(7):
                        self.tableWidget.item(row,i).setBackground(Qt.black)   #设置背景颜色
                        self.tableWidget.item(row,i).setForeground(QColor('#66FF66'))     #设置字体颜色
            #IGMP
            elif packet[IP].proto == 2:
                for i in range(7):
                    self.tableWidget.item(row,i).setBackground(QColor('#FFCCFF'))   #设置背景颜色
        #ARP
        elif type == 0x806 :
            #ARP坏包
            if packet.haslayer('ARP') == 0:
                for i in range(7):
                    self.tableWidget.item(row,i).setBackground(Qt.black)   #设置背景颜色
                    self.tableWidget.item(row,i).setForeground(Qt.red)     #设置字体颜色
            else:
                for i in range(7):
                    self.tableWidget.item(row,i).setBackground(QColor('#FFFFCC'))   #设置背景颜色


    #鼠标左键单击显示详细信息
    def clickInfo(self):
        row = self.tableWidget.currentRow()     #获取当前行数
        p = self.tableWidget.item(row,7).text()
        packet = scapy.layers.l2.Ether(p.encode('Windows-1252'))
        num = self.tableWidget.item(row,0).text()
        Time = self.tableWidget.item(row,1).text()
        length = self.tableWidget.item(row,5).text()
        iface = self.iface
        import time
        timeformat = time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(packet.time))
        self.treeWidget.clear()
        self.treeWidget.setColumnCount(1)

        #Frame
        Frame = QtWidgets.QTreeWidgetItem(self.treeWidget)
        Frame.setText(0,'Frame %s：%s bytes on %s' % (num,length,iface))
        FrameIface = QtWidgets.QTreeWidgetItem(Frame)
        FrameIface.setText(0,'网卡：%s' % iface)
        FrameArrivalTime = QtWidgets.QTreeWidgetItem(Frame)
        FrameArrivalTime.setText(0,'到达时间：%s' % timeformat)
        FrameTime = QtWidgets.QTreeWidgetItem(Frame)
        FrameTime.setText(0,'距离第一帧时间：%s' % Time)
        FrameNumber = QtWidgets.QTreeWidgetItem(Frame)
        FrameNumber.setText(0,'序号：%s' % num)
        FrameLength = QtWidgets.QTreeWidgetItem(Frame)
        FrameLength.setText(0,'帧长度：%s' % length)

        #Ethernet
        Ethernet = QtWidgets.QTreeWidgetItem(self.treeWidget)
        Ethernet.setText(0,'Ethernet，源MAC地址(src)：'+ packet.src + '，目的MAC地址(dst)：'+packet.dst)
        EthernetDst = QtWidgets.QTreeWidgetItem(Ethernet)
        EthernetDst.setText(0,'目的MAC地址(dst)：'+ packet.dst)
        EthernetSrc = QtWidgets.QTreeWidgetItem(Ethernet)
        EthernetSrc.setText(0,'源MAC地址(src)：'+ packet.src)
        try:
            type = packet.type
        except:
            type = 0

        #IP
        if type == 0x800 :
            EthernetType = QtWidgets.QTreeWidgetItem(Ethernet)
            EthernetType.setText(0,'协议类型(type)：IPv4(0x800)')

            IPv4 = QtWidgets.QTreeWidgetItem(self.treeWidget)
            IPv4.setText(0,'IPv4，源ip地址(src)：'+packet[IP].src+'，目的ip地址(dst)：'+packet[IP].dst)
            IPv4Version = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Version.setText(0,'版本(version)：%s'% packet[IP].version)
            IPv4Ihl = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Ihl.setText(0,'包头长度(ihl)：%s' % packet[IP].ihl)
            IPv4Tos = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Tos.setText(0,'服务类型(tos)：%s'% packet[IP].tos)
            IPv4Len = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Len.setText(0,'总长度(len)：%s' % packet[IP].len) #IP报文的总长度。报头的长度和数据部分的长度之和。
            IPv4Id = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Id.setText(0,'标识(id)：%s' % packet[IP].id)  #唯一的标识主机发送的每一分数据报。通常每发送一个报文，它的值加一。当IP报文长度超过传输网络的MTU（最大传输单元）时必须分片，这个标识字段的值被复制到所有数据分片的标识字段中，使得这些分片在达到最终目的地时可以依照标识字段的内容重新组成原先的数据。
            IPv4Flags = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Flags.setText(0,'标志(flags)：%s' % packet[IP].flags) #R、DF、MF三位。目前只有后两位有效，DF位：为1表示不分片，为0表示分片。MF：为1表示“更多的片”，为0表示这是最后一片。
            IPv4Frag = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4FlagsDF = QtWidgets.QTreeWidgetItem(IPv4Flags)
            IPv4FlagsDF.setText(0,'不分段(DF)：%s' % packet[IP].flags.DF)
            IPv4FlagsMF = QtWidgets.QTreeWidgetItem(IPv4Flags)
            IPv4FlagsMF.setText(0,'更多分段(MF)：%s' % packet[IP].flags.MF)
            IPv4Frag.setText(0,'片位移(frag)：%s ' % packet[IP].frag)  #本分片在原先数据报文中相对首位的偏移位。（需要再乘以8）
            IPv4Ttl = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Ttl.setText(0,'生存时间(ttl)：%s' % packet[IP].ttl)

            #TCP
            if packet[IP].proto == 6:
                if packet.haslayer('TCP'):
                    IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
                    IPv4Proto.setText(0,'协议类型(proto)：TCP(6)')
                    tcp = QtWidgets.QTreeWidgetItem(self.treeWidget)
                    tcp.setText(0,'TCP，源端口(sport)：%s，目的端口(dport)：%s，Seq：%s，Ack：%s' % (packet[TCP].sport,packet[TCP].dport,packet[TCP].seq,packet[TCP].ack))
                    tcpSport = QtWidgets.QTreeWidgetItem(tcp)
                    tcpSport.setText(0,'源端口(sport)：%s' % packet[TCP].sport)
                    tcpDport = QtWidgets.QTreeWidgetItem(tcp)
                    tcpDport.setText(0,'目的端口(dport)：%s' % packet[TCP].dport)
                    tcpSeq = QtWidgets.QTreeWidgetItem(tcp)
                    tcpSeq.setText(0,'序号(Seq)：%s' % packet[TCP].seq)
                    tcpAck = QtWidgets.QTreeWidgetItem(tcp)
                    tcpAck.setText(0,'确认号(Ack)：%s' % packet[TCP].ack)
                    tcpDataofs = QtWidgets.QTreeWidgetItem(tcp)
                    tcpDataofs.setText(0,'数据偏移(dataofs)：%s' % packet[TCP].dataofs)
                    tcpReserved = QtWidgets.QTreeWidgetItem(tcp)
                    tcpReserved.setText(0,'保留(reserved)：%s' % packet[TCP].reserved)
                    tcpFlags = QtWidgets.QTreeWidgetItem(tcp)
                    tcpFlags.setText(0,'标志(flags)：%s' % packet[TCP].flags)
                    tcpFlagsACK = QtWidgets.QTreeWidgetItem(tcpFlags)
                    tcpFlagsACK.setText(0,'确认(ACK)：%s' % packet[TCP].flags.A)
                    tcpFlagsRST = QtWidgets.QTreeWidgetItem(tcpFlags)
                    tcpFlagsRST.setText(0,'重新连接(RST)：%s' % packet[TCP].flags.R)
                    tcpFlagsSYN = QtWidgets.QTreeWidgetItem(tcpFlags)
                    tcpFlagsSYN.setText(0,'发起连接(SYN)：%s' % packet[TCP].flags.S)
                    tcpFlagsFIN = QtWidgets.QTreeWidgetItem(tcpFlags)
                    tcpFlagsFIN.setText(0,'释放连接(FIN)：%s' % packet[TCP].flags.F)
                    tcpFlagsURG = QtWidgets.QTreeWidgetItem(tcpFlags)
                    tcpFlagsURG.setText(0,'紧急指针(URG)：%s' % packet[TCP].flags.U)
                    tcpFlagsPSH = QtWidgets.QTreeWidgetItem(tcpFlags)
                    tcpFlagsPSH.setText(0,'非缓冲区(PSH)：%s' % packet[TCP].flags.P)
                    tcpWindow = QtWidgets.QTreeWidgetItem(tcp)
                    tcpWindow.setText(0,'窗口(window)：%s' % packet[TCP].window)
                    tcpChksum = QtWidgets.QTreeWidgetItem(tcp)
                    tcpChksum.setText(0,'校验和(chksum)：0x%x' % packet[TCP].chksum)
                    tcpUrgptr = QtWidgets.QTreeWidgetItem(tcp)
                    tcpUrgptr.setText(0,'紧急指针(urgptr)：%s' % packet[TCP].urgptr)  #只有当U R G标志置1时紧急指针才有效。紧急指针是一个正的偏移量，和序号字段中的值相加表示紧急数据最后一个字节的序号。
                    tcpOptions = QtWidgets.QTreeWidgetItem(tcp)
                    tcpOptions.setText(0,'选项(options)：%s' % packet[TCP].options)

            #UDP
            elif packet[IP].proto == 17:
                IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
                IPv4Proto.setText(0,'协议类型(proto)：UDP(17)')
                udp = QtWidgets.QTreeWidgetItem(self.treeWidget)
                udp.setText(0,'UDP，源端口(sport)：%s，目的端口(dport)：%s'% (packet[UDP].sport , packet[UDP].dport))
                udpSport = QtWidgets.QTreeWidgetItem(udp)
                udpSport.setText(0,'源端口(sport)：%s' % packet[UDP].sport)
                udpDport = QtWidgets.QTreeWidgetItem(udp)
                udpDport.setText(0,'目的端口(dport)：%s' % packet[UDP].dport)
                udpLen = QtWidgets.QTreeWidgetItem(udp)
                udpLen.setText(0,'长度(len)：%s' % packet[UDP].len)
                udpChksum = QtWidgets.QTreeWidgetItem(udp)
                udpChksum.setText(0,'校验和(chksum)：0x%x' % packet[UDP].chksum)
                #DNS
                if packet.haslayer('DNS'):
                    pass

            #ICMP
            elif packet[IP].proto == 1:
                IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
                IPv4Proto.setText(0,'协议类型(proto)：ICMP(1)')
                icmp = QtWidgets.QTreeWidgetItem(self.treeWidget)
                icmp.setText(0,'ICMP')
                icmpType = QtWidgets.QTreeWidgetItem(icmp)
                if packet[ICMP].type == 8:
                    icmpType.setText(0,'类型(type)：%s (Echo (ping) request)' % packet[ICMP].type)
                elif packet[ICMP].type == 0:
                    icmpType.setText(0,'类型(type)：%s (Echo (ping) reply)' % packet[ICMP].type)
                else:
                    icmpType.setText(0,'类型(type)：%s' % packet[ICMP].type)  #占一字节，标识ICMP报文的类型，目前已定义了14种，从类型值来看ICMP报文可以分为两大类。第一类是取值为1~127的差错报文，第2类是取值128以上的信息报文。
                icmpCode = QtWidgets.QTreeWidgetItem(icmp)
                icmpCode.setText(0,'代码(code)：%s' % packet[ICMP].code)  #占一字节，标识对应ICMP报文的代码。它与类型字段一起共同标识了ICMP报文的详细类型。
                icmpChksum = QtWidgets.QTreeWidgetItem(icmp)
                icmpChksum.setText(0,'校验和(chksum)：0x%x' % packet[ICMP].chksum)
                icmpId = QtWidgets.QTreeWidgetItem(icmp)
                icmpId.setText(0,'标识(id)：%s' % packet[ICMP].id)  #占两字节，用于标识本ICMP进程，但仅适用于回显请求和应答ICMP报文，对于目标不可达ICMP报文和超时ICMP报文等，该字段的值为0。
                icmpSeq = QtWidgets.QTreeWidgetItem(icmp)
                icmpSeq.setText(0,'seq：%s' % packet[ICMP].seq)
                icmpTs_ori = QtWidgets.QTreeWidgetItem(icmp)
                icmpTs_ori.setText(0,'ts_ori：%s' % packet[ICMP].ts_ori)
                icmpTs_rx = QtWidgets.QTreeWidgetItem(icmp)
                icmpTs_rx.setText(0,'ts_rx：%s' % packet[ICMP].ts_rx)
                icmpTs_tx = QtWidgets.QTreeWidgetItem(icmp)
                icmpTs_tx.setText(0,'ts_tx：%s' % packet[ICMP].ts_tx)
                icmpGw = QtWidgets.QTreeWidgetItem(icmp)
                icmpGw.setText(0,'gw：%s' % packet[ICMP].gw)
                icmpPtr = QtWidgets.QTreeWidgetItem(icmp)
                icmpPtr.setText(0,'ptr：%s' % packet[ICMP].ptr)
                icmpReserved = QtWidgets.QTreeWidgetItem(icmp)
                icmpReserved.setText(0,'reserved：%s' % packet[ICMP].reserved)
                icmpLength = QtWidgets.QTreeWidgetItem(icmp)
                icmpLength.setText(0,'length：%s' % packet[ICMP].length)
                icmpAddr_mask = QtWidgets.QTreeWidgetItem(icmp)
                icmpAddr_mask.setText(0,'addr_mask：%s' % packet[ICMP].addr_mask)
                icmpnexthopmtu = QtWidgets.QTreeWidgetItem(icmp)
                icmpnexthopmtu.setText(0,'nexthopmtu：%s' % packet[ICMP].nexthopmtu)

            #IGMP
            elif packet[IP].proto == 2:
                IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
                IPv4Proto.setText(0,'协议类型(proto)：IGMP(2)')
                igmp = QtWidgets.QTreeWidgetItem(self.treeWidget)
                igmp.setText(0,'IGMP')
                igmpCopy_flag = QtWidgets.QTreeWidgetItem(igmp)
                igmpCopy_flag.setText(0,'copy_flag：%s' % packet[IPOption_Router_Alert].copy_flag)
                igmpOptclass = QtWidgets.QTreeWidgetItem(igmp)
                igmpOptclass.setText(0,'optclass：%s' % packet[IPOption_Router_Alert].optclass)
                igmpOption = QtWidgets.QTreeWidgetItem(igmp)
                igmpOption.setText(0,'option：%s' % packet[IPOption_Router_Alert].option)
                igmpLength = QtWidgets.QTreeWidgetItem(igmp)
                igmpLength.setText(0,'length：%s' % packet[IPOption_Router_Alert].length)
                igmpAlert = QtWidgets.QTreeWidgetItem(igmp)
                igmpAlert.setText(0,'alert：%s' % packet[IPOption_Router_Alert].alert)
            else:
                IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
                IPv4Proto.setText(0,'协议类型(proto)：%s'% packet[IP].proto)

            IPv4Chksum = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Chksum.setText(0,'校验和(chksum)：0x%x' % packet[IP].chksum)
            IPv4Src = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Src.setText(0,'源IP地址(src)：%s' % packet[IP].src)
            IPv4Dst = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Dst.setText(0,'目的IP地址(dst)：%s' % packet[IP].dst)
            IPv4Options = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Options.setText(0,'可选部分(options)：%s' %packet[IP].options)

        #ARP
        elif type == 0x806 :
            EthernetType = QtWidgets.QTreeWidgetItem(Ethernet)
            EthernetType.setText(0,'协议类型(type)：ARP(0x806)')
            arp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            arp.setText(0,'ARP')
            arpHwtype = QtWidgets.QTreeWidgetItem(arp)
            arpHwtype.setText(0,'硬件类型(hwtype)：0x%x' % packet[ARP].hwtype) #1代表是以太网。
            arpPtype = QtWidgets.QTreeWidgetItem(arp)
            arpPtype.setText(0,'协议类型(ptype)：0x%x' % packet[ARP].ptype) #表明上层协议的类型,这里是0x0800,表示上层协议是IP协议
            arpHwlen = QtWidgets.QTreeWidgetItem(arp)
            arpHwlen.setText(0,'硬件地址长度(hwlen)：%s' % packet[ARP].hwlen)
            arpPlen = QtWidgets.QTreeWidgetItem(arp)
            arpPlen.setText(0,'协议长度(plen)：%s' % packet[ARP].plen)
            arpOp = QtWidgets.QTreeWidgetItem(arp)
            if packet[ARP].op == 1:  #request
                arpOp.setText(0,'操作类型(op)：request (%s)' % packet[ARP].op)
            elif packet[ARP].op == 2:
                arpOp.setText(0,'操作类型(op)：reply (%s)' % packet[ARP].op)
            else:
                arpOp.setText(0,'操作类型(op)：%s' % packet[ARP].op) #在报文中占2个字节,1表示ARP请求,2表示ARP应答,3表示RARP请求,4表示RARP应答
            arpHwsrc = QtWidgets.QTreeWidgetItem(arp)
            arpHwsrc.setText(0,'源MAC地址(hwsrc)：%s' % packet[ARP].hwsrc)
            arpPsrc = QtWidgets.QTreeWidgetItem(arp)
            arpPsrc.setText(0,'源IP地址(psrc)：%s' % packet[ARP].psrc)
            arpHwdst = QtWidgets.QTreeWidgetItem(arp)
            arpHwdst.setText(0,'目的MAC地址(hwdst)：%s' % packet[ARP].hwdst)
            arpPdst = QtWidgets.QTreeWidgetItem(arp)
            arpPdst.setText(0,'目的IP地址(pdst)：%s' % packet[ARP].pdst)


    #数据包统计
    def statistics(self):
        global count
        global display
        if count != 0:
            self.statusbar.showMessage('捕获：%s' % (count))


    #保存所有数据包
    def savePackets(self):
        path, filetype = QtWidgets.QFileDialog.getSaveFileName(None,
                                    "选择保存路径",
                                    "./",
                                    "pcap文件(*.cap);;全部(*)")
        if path == "":
            return
        if os.path.exists(os.path.dirname(path)) == False:
            QtWidgets.QMessageBox.critical(None,"错误","路径不存在")
            return
        packets = scapy.plist.PacketList(self.packetList)
        wrpcap(path,packets)
        QtWidgets.QMessageBox.information(None,"成功","保存成功")


#嗅探线程
class SnifferThread(QtCore.QThread):
    HandleSignal = QtCore.pyqtSignal(scapy.layers.l2.Ether)
    def __init__(self,filter,iface):
        super().__init__()
        self.filter = filter
        self.iface = iface
    def run(self):
        sniff(filter=self.filter,iface=self.iface,prn=lambda x:self.HandleSignal.emit(x))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Alex_sniffer()
    ui.setupUi(MainWindow)
    ui.setSlot()
    MainWindow.show()
    sys.exit(app.exec_())