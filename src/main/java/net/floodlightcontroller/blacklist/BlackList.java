package net.floodlightcontroller.blacklist;

import java.text.DateFormat;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.IFloodlightProviderService;

import java.util.ArrayList;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.packet.*;

import org.projectfloodlight.openflow.types.*;

public class BlackList implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
    int h1h4_count = 0;
    int h1h5_count = 0;
    int h1h6_count = 0;
    int h2h4_count = 0;
    int h2h5_count = 0;
    int h2h6_count = 0;
    int h3h4_count = 0;
    int h3h5_count = 0;
    int h3h6_count = 0;
    int packetLimit = 5;
    int maxLimit = 25;
	String poczatek = "8:00:00 AM";
	String koniec = "8:00:00 PM";
    
	@Override
	public String getName() {
		 return BlackList.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
	    Collection<Class<? extends IFloodlightService>> l =
	            new ArrayList<Class<? extends IFloodlightService>>();
	        l.add(IFloodlightProviderService.class);
	        return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
	    floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
	    macAddresses = new ConcurrentSkipListSet<Long>();
	    logger = LoggerFactory.getLogger(BlackList.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		        
		String currentTime = DateFormat.getTimeInstance().format(System.currentTimeMillis());
		System.out.println("Current time: " + currentTime);
		int isAfter = currentTime.compareTo(poczatek);
		int isBefore = currentTime.compareTo(koniec);
		if (isAfter > 0 && isBefore < 0){
		    packetLimit = 5;
		    maxLimit = 25;
			System.out.println("Jest miedzy 8 a 16");
		} else {
		    packetLimit = 10;
		    maxLimit = 50;
			System.out.println("Jest miedzy po 16 i przed 8");
		}

		
        switch (msg.getType()) {
        case PACKET_IN:
            Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

            if (eth.getEtherType() == EthType.IPv4) {
            	IPv4 ipv4 = (IPv4) eth.getPayload();
            	
                    IPv4Address srcIP = ipv4.getSourceAddress();
                    IPv4Address dstIP = ipv4.getDestinationAddress();
                    String srcIPstring = srcIP.toString();
                    String dstIPstring = dstIP.toString();

                    System.out.println("srcIP = " + srcIPstring);
                    System.out.println("dstIP = " + dstIPstring);
                    if (srcIPstring.equals("192.168.0.11")){
                    	System.out.println("###src for srcIP h1 = " + srcIPstring);
                    	if (dstIPstring.equals("172.16.0.11")){
                    		h1h4_count ++;
                    		System.out.println("h1h4_count for srcIP h1 = " + h1h4_count);
                    		if (h1h4_count > packetLimit) {
                    			if (h1h4_count > maxLimit) {
                    				h1h4_count = 0;
                    			} else {
                				OFPacketIn pi = (OFPacketIn) msg;
                				Match m = pi.getMatch();
                				dropFlowMod(sw, m);
                            	return Command.STOP;
                    			}
                    		} 
                    	} else if (dstIPstring.equals("172.16.0.12")){
                    		h1h5_count ++;
                    		System.out.println("h1h5_count for srcIP h1 = " + h1h5_count);
                    		if (h1h5_count > packetLimit) {
                    			if (h1h5_count > maxLimit) {
                    				h1h5_count = 0;
                    			} else {
                				OFPacketIn pi = (OFPacketIn) msg;
                				Match m = pi.getMatch();
                				dropFlowMod(sw, m);
                            	return Command.STOP;
                    			}
                    		}	
                    	} else if (dstIPstring.equals("172.16.0.13")){
                    		h1h6_count ++;
                    		System.out.println("h1h6_count for srcIP h1 = " + h1h6_count);
                    		if (h1h6_count > packetLimit) {
                    			if (h1h6_count > maxLimit) {
                    				h1h6_count = 0;
                    			} else {
                				OFPacketIn pi = (OFPacketIn) msg;
                				Match m = pi.getMatch();
                				dropFlowMod(sw, m);
                            	return Command.STOP;
                    			}
                    		}	
                    	}
                    	
                    } else if (srcIPstring.equals("192.168.0.12")){
                    	if (dstIPstring.equals("172.16.0.11")){
                    		h2h4_count ++;
                    		System.out.println("h2h4_count for srcIP h1 = " + h2h4_count);
                    		if (h2h4_count > packetLimit) {
                    			if (h2h4_count > maxLimit) {
                    				h2h4_count = 0;
                    			} else {
                				OFPacketIn pi = (OFPacketIn) msg;
                				Match m = pi.getMatch();
                				dropFlowMod(sw, m);
                            	return Command.STOP;
                    			}
                    		}	
                    	} else if (dstIPstring.equals("172.16.0.12")){
                    		h2h5_count ++;
                    		System.out.println("h2h5_count for srcIP h1 = " + h2h5_count);
                    		if (h2h5_count > packetLimit) {
                    			if (h2h5_count > maxLimit) {
                    				h2h5_count = 0;
                    			} else {
                				OFPacketIn pi = (OFPacketIn) msg;
                				Match m = pi.getMatch();
                				dropFlowMod(sw, m);
                            	return Command.STOP;
                    			}
                    		}	
                    	} else if (dstIPstring.equals("172.16.0.13")){
                    		h2h6_count ++;
                    		System.out.println("h2h6_count for srcIP h1 = " + h2h6_count);
                    		if (h2h6_count > packetLimit) {
                    			if (h2h6_count > maxLimit) {
                    				h2h6_count = 0;
                    			} else {
                				OFPacketIn pi = (OFPacketIn) msg;
                				Match m = pi.getMatch();
                				dropFlowMod(sw, m);
                            	return Command.STOP;
                    			}
                    		}	
                    	
                    } else if (srcIPstring.equals("192.168.0.13")){
                    	if (dstIPstring.equals("172.16.0.11")){
                    		h3h4_count ++;
                    		System.out.println("h3h4_count for srcIP h1 = " + h3h4_count);
                    		if (h3h4_count > packetLimit) {
                    			if (h3h4_count > maxLimit) {
                    				h3h4_count = 0;
                    			} else {
                				OFPacketIn pi = (OFPacketIn) msg;
                				Match m = pi.getMatch();
                				dropFlowMod(sw, m);
                            	return Command.STOP;
                    			}
                    		}	
                    	} else if (dstIPstring.equals("172.16.0.12")){
                    		h3h5_count ++;
                    		System.out.println("h3h5_count for srcIP h1 = " + h3h5_count);
                    		if (h3h5_count > packetLimit) {
                    			if (h3h5_count > maxLimit) {
                    				h3h5_count = 0;
                    			} else {
                				OFPacketIn pi = (OFPacketIn) msg;
                				Match m = pi.getMatch();
                				dropFlowMod(sw, m);
                            	return Command.STOP;
                    			}
                    		}	
                    	} else if (dstIPstring.equals("172.16.0.13")){
                    		h3h6_count ++;
                    		System.out.println("h3h6_count for srcIP h1 = " + h3h6_count);
                    		if (h3h6_count > packetLimit) {
                    			if (h3h6_count > maxLimit) {
                    				h3h6_count = 0;
                    			} else {
                				OFPacketIn pi = (OFPacketIn) msg;
                				Match m = pi.getMatch();
                				dropFlowMod(sw, m);
                            	return Command.STOP;
                    			}
                    		}	
                    	}
                    }
                }
            }
            break;
        default:
            break;
        }
        
        //---------
        return Command.CONTINUE;
	}
	
	// Flow-Mod defaults
    protected static final short FLOWMOD_IDLE_TIMEOUT = 0; // in seconds
    protected static final short FLOWMOD_HARD_TIMEOUT = 1; // 
    protected static final short FLOWMOD_PRIORITY = 100;
    
    public static final int NO_ARP_SPOOF_APP_ID = 1;
    public static final int APP_ID_BITS = 12;
    public static final int APP_ID_SHIFT = (64 - APP_ID_BITS);
    public static final long NO_ARP_SPOOF_COOKIE = (long) (NO_ARP_SPOOF_APP_ID & ((1 << APP_ID_BITS) - 1)) << APP_ID_SHIFT;

	private void dropFlowMod(IOFSwitch sw, Match match) {

        OFFlowMod.Builder fmb;
		List<OFAction> actions = new ArrayList<OFAction>();

        fmb = sw.getOFFactory().buildFlowAdd();
        fmb.setMatch(match);
        fmb.setIdleTimeout(FLOWMOD_IDLE_TIMEOUT);
        fmb.setHardTimeout(FLOWMOD_HARD_TIMEOUT);
        fmb.setPriority(FLOWMOD_PRIORITY);
        fmb.setCookie((U64.of(NO_ARP_SPOOF_COOKIE)));
        fmb.setBufferId(OFBufferId.NO_BUFFER);        
        fmb.setActions(actions);

        sw.write(fmb.build());
    }
}
