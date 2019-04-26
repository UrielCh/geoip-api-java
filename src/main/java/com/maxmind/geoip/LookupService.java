/**
 * LookupService.java
 *
 * Copyright (C) 2003 MaxMind LLC.  All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package com.maxmind.geoip;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.InetAddress;
import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.util.EnumSet;
import java.util.Hashtable;
import java.util.StringTokenizer;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import static com.maxmind.geoip.DbOption.*;
import static com.maxmind.geoip.DatabaseInfo.*;

/**
 * Provides a lookup service for information based on an IP address. The
 * location of a database file is supplied when creating a lookup service
 * instance. The edition of the database determines what information is
 * available about an IP address. See the DatabaseInfo class for further
 * details.
 * <p>
 * 
 * The following code snippet demonstrates looking up the country that an IP
 * address is from:
 * 
 * <pre>
 * // First, create a LookupService instance with the location of the database.
 * LookupService lookupService = new LookupService(&quot;c:\\geoip.dat&quot;);
 * // Assume we have a String ipAddress (in dot-decimal form).
 * Country country = lookupService.getCountry(ipAddress);
 * System.out.println(&quot;The country is: &quot; + country.getName());
 * System.out.println(&quot;The country code is: &quot; + country.getCode());
 * </pre>
 * 
 * In general, a single LookupService instance should be created and then reused
 * repeatedly.
 * <p>
 * 
 * <i>Tip:</i> Those deploying the GeoIP API as part of a web application may
 * find it difficult to pass in a File to create the lookup service, as the
 * location of the database may vary per deployment or may even be part of the
 * web-application. In this case, the database should be added to the classpath
 * of the web-app. For example, by putting it into the WEB-INF/classes directory
 * of the web application. The following code snippet demonstrates how to create
 * a LookupService using a database that can be found on the classpath:
 * 
 * <pre>
 * String fileName = getClass().getResource(&quot;/GeoIP.dat&quot;).toExternalForm().substring(6);
 * LookupService lookupService = new LookupService(fileName);
 * </pre>
 * 
 * @author Matt Tucker (matt@jivesoftware.com)
 */
public class LookupService {

	/**
	 * Database file.
	 */
	private RandomAccessFile file = null;
	private File databaseFile = null;

	/**
	 * Information about the database.
	 */
	private DatabaseInfo databaseInfo = null;

	/**
	 * The database type. Default is the country edition.
	 */
	byte databaseType = COUNTRY_EDITION;

	int databaseSegments;
	int recordLength;

	String licenseKey;
	int dnsService = 0;
	EnumSet<DbOption> dboptions = EnumSet.noneOf(DbOption.class);
	byte dbbuffer[];
	byte index_cache[];
	long mtime;
	int last_netmask;

	private final static int US_OFFSET = 1;
	private final static int CANADA_OFFSET = 677;
	private final static int WORLD_OFFSET = 1353;

	private final static int FIPS_RANGE = 360;

	private final static int COUNTRY_BEGIN = 16776960;

	private final static int STATE_BEGIN_REV0 = 16700000;
	private final static int STATE_BEGIN_REV1 = 16000000;

	private final static int STRUCTURE_INFO_MAX_SIZE = 20;
	private final static int DATABASE_INFO_MAX_SIZE = 100;

	public final static int GEOIP_STANDARD = 0;

	private final static int SEGMENT_RECORD_LENGTH = 3;
	private final static int STANDARD_RECORD_LENGTH = 3;
	private final static int ORG_RECORD_LENGTH = 4;
	private final static int MAX_RECORD_LENGTH = 4;

	private final static int MAX_ORG_RECORD_LENGTH = 300;
	private final static int FULL_RECORD_LENGTH = 60;

	private final Country UNKNOWN_COUNTRY = new Country("--", "N/A");

	public RandomAccessFile getRAFile() {
		return file;
	}

	public int getDatabaseSegments() {
		return databaseSegments;
	}

	public int getRecordLength() {
		return recordLength;
	}

	/**
	 * Create a new distributed lookup service using the license key
	 * 
	 * @param databaseFile
	 *            String representation of the database file.
	 * @param licenseKey
	 *            license key provided by Maxmind to access distributed service
	 */
	public LookupService(String databaseFile, String licenseKey) throws IOException {
		this(new File(databaseFile));
		this.licenseKey = licenseKey;
		dnsService = 1;
	}

	/**
	 * Create a new distributed lookup service using the license key
	 * 
	 * @param databaseFile
	 *            the database file.
	 * @param licenseKey
	 *            license key provided by Maxmind to access distributed service
	 */
	public LookupService(File databaseFile, String licenseKey) throws IOException {
		this(databaseFile);
		this.licenseKey = licenseKey;
		dnsService = 1;
	}

	/**
	 * Create a new distributed lookup service using the license key
	 * 
	 * @param options
	 *            Resevered for future use
	 * @param licenseKey
	 *            license key provided by Maxmind to access distributed service
	 */
	public LookupService(int options, String licenseKey) throws IOException {
		this.licenseKey = licenseKey;
		dnsService = 1;
		init();
	}

	/**
	 * Create a new lookup service using the specified database file.
	 * 
	 * @param databaseFile
	 *            String representation of the database file.
	 * @throws java.io.IOException
	 *             if an error occured creating the lookup service from the
	 *             database file.
	 */
	public LookupService(String databaseFile) throws IOException {
		this(new File(databaseFile));
	}

	/**
	 * Create a new lookup service using the specified database file.
	 * 
	 * @param databaseFile
	 *            the database file.
	 * @throws java.io.IOException
	 *             if an error occured creating the lookup service from the
	 *             database file.
	 */
	public LookupService(File databaseFile) throws IOException {
		this.databaseFile = databaseFile;
		this.file = new RandomAccessFile(databaseFile, "r");
		init();
	}

	/**
	 * Create a new lookup service using the specified database file.
	 * 
	 * @param databaseFile
	 *            String representation of the database file.
	 * @param options
	 *            database flags to use when opening the database GEOIP_STANDARD
	 *            read database from disk GEOIP_MEMORY_CACHE cache the database
	 *            in RAM and read it from RAM
	 * @throws java.io.IOException
	 *             if an error occured creating the lookup service from the
	 *             database file.
	 */
	public LookupService(String databaseFile, EnumSet<DbOption> options) throws IOException {
		this(new File(databaseFile), options);
	}

	public LookupService(String databaseFile, DbOption... options) throws IOException {
		this(new File(databaseFile), options);
	}

	/**
	 * Create a new lookup service using the specified database file.
	 * 
	 * @param databaseFile
	 *            the database file.
	 * @param options
	 *            database flags to use when opening the database GEOIP_STANDARD
	 *            read database from disk GEOIP_MEMORY_CACHE cache the database
	 *            in RAM and read it from RAM
	 * @throws java.io.IOException
	 *             if an error occured creating the lookup service from the
	 *             database file.
	 */
	public LookupService(File databaseFile, EnumSet<DbOption> options) throws IOException {
		this.databaseFile = databaseFile;
		this.file = new RandomAccessFile(databaseFile, "r");
		dboptions = options;
		init();
	}

	public LookupService(File databaseFile, DbOption... options) throws IOException {
		this.databaseFile = databaseFile;
		this.file = new RandomAccessFile(databaseFile, "r");
		for (DbOption opt : options)
			this.dboptions.add(opt);
		init();
	}

	/**
	 * Reads meta-data from the database file.
	 * 
	 * @throws java.io.IOException
	 *             if an error occurs reading from the database file.
	 */
	private void init() throws IOException {
		byte[] delim = new byte[3];

		if (file == null) {
			return;
		}
		if (dboptions.contains(GEOIP_CHECK_CACHE)) {
			mtime = databaseFile.lastModified();
		}
		file.seek(file.length() - 3);
		for (int i = 0; i < STRUCTURE_INFO_MAX_SIZE; i++) {
			file.readFully(delim);

			if (delim[0] != -1 || delim[1] != -1 || delim[2] != -1) {
				file.seek(file.getFilePointer() - 4);
				continue;
			}

			databaseType = file.readByte();
			if (databaseType >= 106) {
				// Backward compatibility with databases from April 2003 and
				// earlier
				databaseType -= 105;
			}

			// Determine the database type.
			if (databaseType == REGION_EDITION_REV0) {
				databaseSegments = STATE_BEGIN_REV0;
				recordLength = STANDARD_RECORD_LENGTH;
			} else if (databaseType == REGION_EDITION_REV1) {
				databaseSegments = STATE_BEGIN_REV1;
				recordLength = STANDARD_RECORD_LENGTH;
			} else if (databaseType == CITY_EDITION_REV0 || databaseType == CITY_EDITION_REV1
					|| databaseType == ORG_EDITION || databaseType == ISP_EDITION || databaseType == ASNUM_EDITION) {
				databaseSegments = 0;
				if (databaseType == CITY_EDITION_REV0 || databaseType == CITY_EDITION_REV1
						|| databaseType == ASNUM_EDITION) {
					recordLength = STANDARD_RECORD_LENGTH;
				} else { // ISP_EDITION ORG_EDITION
					recordLength = ORG_RECORD_LENGTH;
				}
				byte[] buf = new byte[SEGMENT_RECORD_LENGTH];
				file.readFully(buf);
				databaseSegments = read3ByteInt(buf, 0);
			} else {
				System.out.println("Format inconue databaseType:" + databaseType);
			}
			break;
		}

		if ((databaseType == COUNTRY_EDITION) || (databaseType == COUNTRY_EDITION_V6)
				|| (databaseType == PROXY_EDITION) || (databaseType == NETSPEED_EDITION)) {
			databaseSegments = COUNTRY_BEGIN;
			recordLength = STANDARD_RECORD_LENGTH;
		}
		if (dboptions.contains(GEOIP_MEMORY_CACHE)) {
			int l = (int) file.length();
			dbbuffer = new byte[l];
			file.seek(0);
			file.readFully(dbbuffer, 0, l);
			databaseInfo = this.getDatabaseInfo();
			file.close();
		}
		if (dboptions.contains(GEOIP_INDEX_CACHE)) {
			int l = databaseSegments * recordLength * 2;
			index_cache = new byte[l];
			if (index_cache != null) {
				file.seek(0);
				file.readFully(index_cache, 0, l);
			}
		} else {
			index_cache = null;
		}
	}

	/**
	 * Closes the lookup service.
	 */
	public void close() {
		try {
			if (file != null) {
				file.close();
			}
			file = null;
		} catch (Exception e) {
		}
	}

	/**
	 * Returns the country the IP address is in.
	 * 
	 * @param ipAddress
	 *            String version of an IPv6 address, i.e. "::127.0.0.1"
	 * @return the country the IP address is from.
	 */
	public Country getCountryV6(String ipAddress) {
		InetAddress addr;
		try {
			addr = Inet6Address.getByName(ipAddress);
		} catch (UnknownHostException e) {
			return UNKNOWN_COUNTRY;
		}
		return getCountryV6(addr);
	}

	/**
	 * Returns the country the IP address is in.
	 * 
	 * @param ipAddress
	 *            String version of an IP address, i.e. "127.0.0.1"
	 * @return the country the IP address is from.
	 */
	public Country getCountry(String ipAddress) {
		InetAddress addr;
		try {
			addr = InetAddress.getByName(ipAddress);
		} catch (UnknownHostException e) {
			return UNKNOWN_COUNTRY;
		}
		return getCountry(bytesToLong(addr.getAddress()));
	}

	/**
	 * Returns the country the IP address is in.
	 * 
	 * @param ipAddress
	 *            the IP address.
	 * @return the country the IP address is from.
	 */
	public synchronized Country getCountry(InetAddress ipAddress) {
		return getCountry(bytesToLong(ipAddress.getAddress()));
	}

	/**
	 * Returns the country the IP address is in.
	 * 
	 * @param addr
	 *            the IP address as Inet6Address.
	 * @return the country the IP address is from.
	 */
	public Country getCountryV6(InetAddress addr) {
		if (file == null && !dboptions.contains(GEOIP_MEMORY_CACHE)) {
			throw new IllegalStateException("Database has been closed.");
		}
		int ret = seekCountryV6(addr) - COUNTRY_BEGIN;
		if (ret == 0) {
			return UNKNOWN_COUNTRY;
		} else {
			return new Country(LookupServiceData.countryCode[ret], LookupServiceData.countryName[ret]);
		}
	}

	/**
	 * Returns the country the IP address is in.
	 * 
	 * @param ipAddress
	 *            the IP address in long format.
	 * @return the country the IP address is from.
	 */
	public Country getCountry(long ipAddress) {
		if (file == null && !dboptions.contains(GEOIP_MEMORY_CACHE)) {
			throw new IllegalStateException("Database has been closed.");
		}
		int ret = seekCountry(ipAddress) - COUNTRY_BEGIN;
		if (ret == 0) {
			return UNKNOWN_COUNTRY;
		} else {
			return new Country(LookupServiceData.countryCode[ret], LookupServiceData.countryName[ret]);
		}
	}

	public int getID(String ipAddress) {
		InetAddress addr;
		try {
			addr = InetAddress.getByName(ipAddress);
		} catch (UnknownHostException e) {
			return 0;
		}
		return getID(bytesToLong(addr.getAddress()));
	}

	public int getID(InetAddress ipAddress) {
		return getID(bytesToLong(ipAddress.getAddress()));
	}

	public synchronized int getID(long ipAddress) {
		if (file == null && !dboptions.contains(GEOIP_MEMORY_CACHE)) {
			throw new IllegalStateException("Database has been closed.");
		}
		int ret = seekCountry(ipAddress) - databaseSegments;
		return ret;
	}

	public int last_netmask() {
		return this.last_netmask;
	}

	public void netmask(int nm) {
		this.last_netmask = nm;
	}

	/**
	 * Returns information about the database.
	 * 
	 * @return database info.
	 */
	public synchronized DatabaseInfo getDatabaseInfo() {
		if (databaseInfo != null) {
			return databaseInfo;
		}
		try {
			_check_mtime();
			boolean hasStructureInfo = false;
			byte[] delim = new byte[3];
			// Advance to part of file where database info is stored.
			file.seek(file.length() - 3);
			for (int i = 0; i < STRUCTURE_INFO_MAX_SIZE; i++) {
				int read = file.read(delim);
				if (read == 3 && delim[0] == -1 && delim[1] == -1 && delim[2] == -1) {
					hasStructureInfo = true;
					break;
				}
				file.seek(file.getFilePointer() - 4);

			}
			if (hasStructureInfo) {
				file.seek(file.getFilePointer() - 6);
			} else {
				// No structure info, must be pre Sep 2002 database, go back to
				// end.
				file.seek(file.length() - 3);
			}
			// Find the database info string.
			for (int i = 0; i < DATABASE_INFO_MAX_SIZE; i++) {
				file.readFully(delim);
				if (delim[0] == 0 && delim[1] == 0 && delim[2] == 0) {
					byte[] dbInfo = new byte[i];
					file.readFully(dbInfo);
					// Create the database info object using the string.
					this.databaseInfo = new DatabaseInfo(new String(dbInfo));
					return databaseInfo;
				}
				file.seek(file.getFilePointer() - 4);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return new DatabaseInfo("");
	}

	synchronized void _check_mtime() {
		try {
			if (dboptions.contains(GEOIP_CHECK_CACHE)) {
				long t = databaseFile.lastModified();
				if (t != mtime) {
					/* GeoIP Database file updated */
					/* refresh filehandle */
					file.close();
					file = new RandomAccessFile(databaseFile, "r");
					databaseInfo = null;
					init();
				}
			}
		} catch (IOException e) {
			System.out.println("file not found");
		}
	}

	// for GeoIP City only
	public Location getLocation(InetAddress addr) {
		return getLocation(bytesToLong(addr.getAddress()));
	}

	// for GeoIP City only
	public Location getLocation(String str) {
		if (dnsService == 0) {
			InetAddress addr;
			try {
				addr = InetAddress.getByName(str);
			} catch (UnknownHostException e) {
				return null;
			}

			return getLocation(addr);
		} else {
			String str2 = getDnsAttributes(str);
			return getLocationwithdnsservice(str2);
			// TODO if DNS is not available, go to local file as backup
		}
	}

	String getDnsAttributes(String ip) {
		try {
			Hashtable<String, String> env = new Hashtable<String, String>();
			env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
			// TODO don't specify ws1, instead use ns servers for s.maxmind.com
			env.put("java.naming.provider.url", "dns://ws1.maxmind.com/");

			DirContext ictx = new InitialDirContext(env);
			Attributes attrs = ictx.getAttributes(licenseKey + "." + ip + ".s.maxmind.com", new String[] { "txt" });
			// System.out.println(attrs.get("txt").get());
			String str = attrs.get("txt").get().toString();
			return str;
		} catch (NamingException e) {
			// TODO fix this to handle exceptions
			System.out.println("DNS error");
			return null;
		}

	}

	public Location getLocationwithdnsservice(String str) {
		Location record = new Location();
		String key;
		String value;
		StringTokenizer st = new StringTokenizer(str, ";=\"");
		while (st.hasMoreTokens()) {
			key = st.nextToken();
			if (st.hasMoreTokens()) {
				value = st.nextToken();
			} else {
				value = "";
			}
			if (key.equals("co")) {
				Integer i = (Integer) LookupServiceData.hashmapcountryCodetoindex.get(value);
				record.countryCode = value;
				record.countryName = LookupServiceData.countryName[i.intValue()];
			}
			if (key.equals("ci")) {
				record.city = value;
			}
			if (key.equals("re")) {
				record.region = value;
			}
			if (key.equals("zi")) {
				record.postalCode = value;
			}
			// TODO, ISP and Organization
			// if (key.equals("or")) {
			// record.org = value;
			// }
			// if (key.equals("is")) {
			// record.isp = value;
			// }
			if (key.equals("la")) {
				try {
					record.latitude = Float.parseFloat(value);
				} catch (NumberFormatException e) {
					record.latitude = 0;
				}
			}
			if (key.equals("lo")) {
				try {
					record.longitude = Float.parseFloat(value);
				} catch (NumberFormatException e) {
					record.latitude = 0;
				}
			}
			// dm depreciated use me ( metro_code ) instead
			if (key.equals("dm") || key.equals("me")) {
				try {
					record.metro_code = record.dma_code = Integer.parseInt(value);
				} catch (NumberFormatException e) {
					record.metro_code = record.dma_code = 0;
				}
			}
			if (key.equals("ac")) {
				try {
					record.area_code = Integer.parseInt(value);
				} catch (NumberFormatException e) {
					record.area_code = 0;
				}
			}
		}
		return record;
	}

	public synchronized Region getRegion(String str) {
		InetAddress addr;
		try {
			addr = InetAddress.getByName(str);
		} catch (UnknownHostException e) {
			return null;
		}

		return getRegion(bytesToLong(addr.getAddress()));
	}

	public synchronized Region getRegion(long ipnum) {
		Region record = new Region();
		int seek_region = 0;
		if (databaseType == REGION_EDITION_REV0) {
			seek_region = seekCountry(ipnum) - STATE_BEGIN_REV0;
			char ch[] = new char[2];
			if (seek_region >= 1000) {
				record.countryCode = "US";
				record.countryName = "United States";
				ch[0] = (char) (((seek_region - 1000) / 26) + 65);
				ch[1] = (char) (((seek_region - 1000) % 26) + 65);
				record.region = new String(ch);
			} else {
				record.countryCode = LookupServiceData.countryCode[seek_region];
				record.countryName = LookupServiceData.countryName[seek_region];
				record.region = "";
			}
		} else if (databaseType == REGION_EDITION_REV1) {
			seek_region = seekCountry(ipnum) - STATE_BEGIN_REV1;
			char ch[] = new char[2];
			if (seek_region < US_OFFSET) {
				record.countryCode = "";
				record.countryName = "";
				record.region = "";
			} else if (seek_region < CANADA_OFFSET) {
				record.countryCode = "US";
				record.countryName = "United States";
				ch[0] = (char) (((seek_region - US_OFFSET) / 26) + 65);
				ch[1] = (char) (((seek_region - US_OFFSET) % 26) + 65);
				record.region = new String(ch);
			} else if (seek_region < WORLD_OFFSET) {
				record.countryCode = "CA";
				record.countryName = "Canada";
				ch[0] = (char) (((seek_region - CANADA_OFFSET) / 26) + 65);
				ch[1] = (char) (((seek_region - CANADA_OFFSET) % 26) + 65);
				record.region = new String(ch);
			} else {
				record.countryCode = LookupServiceData.countryCode[(seek_region - WORLD_OFFSET) / FIPS_RANGE];
				record.countryName = LookupServiceData.countryName[(seek_region - WORLD_OFFSET) / FIPS_RANGE];
				record.region = "";
			}
		}
		return record;
	}

	public synchronized Location getLocation(long ipnum) {
		byte record_buf[] = new byte[FULL_RECORD_LENGTH];
		int record_pointer = 0;
		int seek_country = 0;
		try {
			seek_country = seekCountry(ipnum);
			if (seek_country == databaseSegments) {
				return null;
			}

			record_pointer = (2 * recordLength) * databaseSegments;
			record_pointer -= databaseSegments;
			record_pointer += seek_country;

			if (dboptions.contains(GEOIP_MEMORY_CACHE)) {
				// read from memory
				System.arraycopy(dbbuffer, record_pointer, record_buf, 0,
						Math.min(dbbuffer.length - record_pointer, FULL_RECORD_LENGTH));
			} else {
				// int p0 = (2 * recordLength) * databaseSegments + 1;
				// int revi = 0;
				// for (int i = 0; i <= 5; i++) {
				// file.seek(p0);
				// file.readFully(record_buf);
				// Location tmp = readLoc(record_buf);
				// System.out.println("T" + revi + " " + tmp);
				// //lastReadSize = 1;
				// revi += lastReadSize;
				//
				// p0 += lastReadSize;
				// }
				// read from disk
				file.seek(record_pointer);
				file.readFully(record_buf);
			}
			return readLoc(record_buf);
		} catch (IOException e) {
			System.err.println("seek: " + record_pointer + " seek_country = " + seek_country + " databaseSegments:"
					+ databaseSegments);
			System.err.println("IO Exception while seting up segments");
		}
		return null;
	}

	int lastReadSize;

	public int getLastReadSize() {
		return lastReadSize;
	}

	public Location readLoc(byte[] record_buf) throws IOException {
		Location record = new Location();
		int record_buf_offset = 0;
		// get country
		record.countryCode = LookupServiceData.countryCode[unsignedByteToInt(record_buf[0])];
		record.countryName = LookupServiceData.countryName[unsignedByteToInt(record_buf[0])];
		record_buf_offset++;

		// get region
		int str_length = 0;
		while (record_buf[record_buf_offset + str_length] != '\0')
			str_length++;
		if (str_length > 0)
			record.region = new String(record_buf, record_buf_offset, str_length);

		// get city
		record_buf_offset += str_length + 1;
		str_length = 0;
		while (record_buf[record_buf_offset + str_length] != '\0')
			str_length++;
		if (str_length > 0)
			record.city = new String(record_buf, record_buf_offset, str_length, "ISO-8859-1");

		// get postal code
		record_buf_offset += str_length + 1;
		str_length = 0;
		while (record_buf[record_buf_offset + str_length] != '\0')
			str_length++;
		if (str_length > 0)
			record.postalCode = new String(record_buf, record_buf_offset, str_length);
		record_buf_offset += str_length + 1;

		// get latitude
		double latitude = read3ByteInt(record_buf, record_buf_offset);
		record.latitude = (float) latitude / 10000 - 180;
		record_buf_offset += 3;

		// get longitude
		double longitude = read3ByteInt(record_buf, record_buf_offset);
		record.longitude = (float) longitude / 10000 - 180;

		record.area_code = record.dma_code = record.metro_code = 0;

		if (databaseType == CITY_EDITION_REV1 && record.countryCode == "US") {
			// get DMA code
			record_buf_offset += 3;
			int metroarea_combo = read3ByteInt(record_buf, record_buf_offset);
			record.metro_code = record.dma_code = metroarea_combo / 1000;
			record.area_code = metroarea_combo % 1000;
		}
		lastReadSize = record_buf_offset + 3;
		return record;
	}

	public String getOrg(InetAddress addr) {
		return getOrg(bytesToLong(addr.getAddress()));
	}

	public String getOrg(String str) {
		InetAddress addr;
		try {
			addr = InetAddress.getByName(str);
		} catch (UnknownHostException e) {
			return null;
		}
		return getOrg(addr);
	}

	// GeoIP Organization and ISP Edition methods
	public synchronized String getOrg(long ipnum) {
		int seek_org;
		int record_pointer;
		int str_length = 0;
		byte[] buf = new byte[MAX_ORG_RECORD_LENGTH];
		String org_buf;

		try {
			seek_org = seekCountry(ipnum);
			if (seek_org == databaseSegments) {
				return null;
			}

			record_pointer = seek_org + (2 * recordLength - 1) * databaseSegments;
			if (dboptions.contains(GEOIP_MEMORY_CACHE)) {
				// read from memory
				System.arraycopy(dbbuffer, record_pointer, buf, 0,
						Math.min(dbbuffer.length - record_pointer, MAX_ORG_RECORD_LENGTH));
			} else {
				// read from disk
				file.seek(record_pointer);
				file.readFully(buf);
			}
			while (buf[str_length] != '\0') {
				str_length++;
			}
			org_buf = new String(buf, 0, str_length, "ISO-8859-1");
			return org_buf;
		} catch (IOException e) {
			System.out.println("IO Exception");
			return null;
		}
	}

	/**
	 * Finds the country index value given an IPv6 address.
	 * 
	 * @param addr
	 *            the ip address to find in long format.
	 * @return the country index.
	 */
	private synchronized int seekCountryV6(InetAddress addr) {
		byte[] v6vec = addr.getAddress();
		byte[] buf = new byte[2 * MAX_RECORD_LENGTH];
		int[] x = new int[2];
		int offset = 0;
		_check_mtime();
		for (int depth = 127; depth >= 0; depth--) {
			if (dboptions.contains(GEOIP_MEMORY_CACHE)) {
				// read from memory
				for (int i = 0; i < 2 * MAX_RECORD_LENGTH; i++) {
					buf[i] = dbbuffer[(2 * recordLength * offset) + i];
				}
			} else if (dboptions.contains(GEOIP_INDEX_CACHE)) {
				// read from index cache
				for (int i = 0; i < 2 * MAX_RECORD_LENGTH; i++) {
					buf[i] = index_cache[(2 * recordLength * offset) + i];
				}
			} else {
				// read from disk
				try {
					file.seek(2 * recordLength * offset);
					file.readFully(buf);
				} catch (IOException e) {
					System.out.println("IO Exception");
				}
			}
			for (int i = 0; i < 2; i++) {
				x[i] = 0;
				for (int j = 0; j < recordLength; j++) {
					int y = unsignedByteToInt(buf[i * recordLength + j]);
					x[i] += (y << (j * 8));
				}
			}

			int bnum = 127 - depth;
			int idx = bnum >> 3;
			int b_mask = 1 << (bnum & 7 ^ 7);
			if ((v6vec[idx] & b_mask) > 0) {
				if (x[1] >= databaseSegments) {
					last_netmask = 128 - depth;
					return x[1];
				}
				offset = x[1];
			} else {
				if (x[0] >= databaseSegments) {
					last_netmask = 128 - depth;
					return x[0];
				}
				offset = x[0];
			}
		}

		// shouldn't reach here
		System.err.println("Error seeking country while seeking " + addr.getHostAddress());
		return 0;
	}

	/**
	 * Finds the country index value given an IP address.
	 * 
	 * @param ipAddress
	 *            the ip address to find in long format.
	 * @return the country index.
	 */
	private synchronized int seekCountry(long ipAddress) {
		byte[] buf = new byte[2 * recordLength]; // 8
		int offset = 0;
		_check_mtime();

		for (int depth = 31; depth >= 0; depth--) {
			if (dboptions.contains(GEOIP_MEMORY_CACHE)) {
				// read from memory
				for (int i = 0; i < 2 * recordLength; i++) {
					buf[i] = dbbuffer[(2 * recordLength * offset) + i];
				}
			} else if (dboptions.contains(GEOIP_INDEX_CACHE)) {
				// read from index cache
				for (int i = 0; i < 2 * recordLength; i++) {
					buf[i] = index_cache[(2 * recordLength * offset) + i];
				}
			} else {
				// read from disk
				try {
					file.seek(2 * recordLength * offset);// 6 * offset
					file.readFully(buf);
				} catch (IOException e) {
					System.out.println("IO Exception");
				}
			}

			int x0, x1;
			if (recordLength == 3) {
				x0 = read3ByteInt(buf, 0);
				x1 = read3ByteInt(buf, 3);
			} else { // (recordLength == 4)
				x0 = read4ByteInt(buf, 0);
				x1 = read4ByteInt(buf, 4);
			}

			if ((ipAddress & (1 << depth)) > 0) { // if 1
				if (x1 >= databaseSegments) {
					last_netmask = 32 - depth;
					return x1;
				}
				offset = x1;
			} else { // if 0
				if (x0 >= databaseSegments) {
					last_netmask = 32 - depth;
					return x0;
				}
				offset = x0;
			}
		}

		// shouldn't reach here
		System.err.println("Error seeking country while seeking " + ipAddress);
		return 0;
	}

	/**
	 * Returns the long version of an IP address given an InetAddress object.
	 * 
	 * @param address
	 *            the InetAddress.
	 * @return the long form of the IP address.
	 */
	private static long bytesToLong(byte[] address) {
		long ipnum = 0;
		for (int i = 0; i < 4; ++i) {
			long y = address[i];
			if (y < 0) {
				y += 256;
			}
			ipnum += y << ((3 - i) * 8);
		}
		return ipnum;
	}

	public static int read4ByteInt(byte[] buf, int offset) {
		int result = 0;
		for (int j = 0; j < 4; j++) {
			result += (unsignedByteToInt(buf[j + offset]) << (j * 8));
		}
		return result;
	}

	// bigEndian
	public static int read3ByteInt(byte[] buf, int offset) {
		int result = 0;
		for (int j = 0; j < 3; j++) {
			result += (unsignedByteToInt(buf[j + offset]) << (j * 8));
		}
		return result;
	}

	private static int unsignedByteToInt(byte b) {
		return (int) b & 0xFF;
	}
}
