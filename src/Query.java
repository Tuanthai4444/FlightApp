import java.io.*;
import java.sql.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.xml.transform.Result;

/**
 * Runs queries against a back-end database
 */
public class Query {
    // DB Connection
    private Connection conn;

    // Password hashing parameter constants
    private static final int HASH_STRENGTH = 65536;
    private static final int KEY_LENGTH = 128;

    // Canned queries
    private static final String CHECK_FLIGHT_CAPACITY = "SELECT capacity FROM Flights WHERE fid = ?";
    private PreparedStatement checkFlightCapacityStatement;

    // For check dangling
    private static final String TRANCOUNT_SQL = "SELECT @@TRANCOUNT AS tran_count";
    private PreparedStatement tranCountStatement;

    private static final String CLEAR_USERS = "DELETE FROM USERS";
    private PreparedStatement clearUsers;

    private static final String CLEAR_RESERVATIONS = "DELETE FROM RESERVATIONS";
    private PreparedStatement clearReservations;

    private static final String CREATE_ACCOUNT = "INSERT INTO USERS (username, password, salt, balance) VALUES (?, ?, ?, ?)";
    private PreparedStatement createAccount;

    private static final String CHECK_ACCOUNT = "SELECT * FROM USERS WHERE username = ?";
    private PreparedStatement checkAccount;

    private static final String DIRECT_FLIGHTS = "SELECT TOP(?)fid, day_of_month, carrier_id, " +
            "flight_num, origin_city, dest_city, actual_time, capacity, price " +
            "FROM Flights " +
            "WHERE origin_city = ? AND dest_city = ? AND day_of_month = ? AND canceled = 0 " +
            "ORDER BY actual_time, fid ASC ";
    private PreparedStatement directFlights;

    private static final String INDIRECT_FLIGHTS = "SELECT TOP(?) F.fid, F.day_of_month, F.carrier_id, " +
            "F.flight_num, F.origin_city, F.dest_city, F.actual_time, F.capacity, F.price, F2.fid AS fid2, " +
            "F2.day_of_month AS day_of_month2, F2.carrier_id AS carrier_id2, F2.flight_num AS flight_num2, " +
            "F2.origin_city AS origin_city2, F2.dest_city AS dest_city2, F2.actual_time AS actual_time2, " +
            "F2.capacity AS capacity2, F2.price AS price2 " +
            "FROM Flights AS F, Flights AS F2 " +
            "WHERE F.origin_city = ? AND F2.dest_city = ? AND F.dest_city = F2.origin_city " +
            "AND F.day_of_month = ? AND F2.day_of_month = F.day_of_month AND " +
            "F.canceled = 0 AND F2.canceled = 0 " +
            "ORDER BY F.actual_time + F2.actual_time, F.fid, F2.fid ASC ";
    private PreparedStatement indirectFlights;

    private static final String CREATE_RESERVATION = "INSERT INTO RESERVATIONS (rid, username, pay_status, fid1, fid2, cancel_status) "
            + " VALUES (?, ?, ?, ?, ?, ?) ";
    private PreparedStatement createReservation;

    private static final String CHECK_RESERVATION_BY_USERNAME = "SELECT * FROM RESERVATIONS WHERE username = ?";
    private PreparedStatement checkReservationByUsername;

    private static final String CHECK_RESERVATION_DATE = "SELECT F.day_of_month FROM FLIGHTS AS F, RESERVATIONS AS R WHERE " +
            " F.fid = R.fid1 AND R.username = ? ";
    private PreparedStatement checkReservationDate;

    private static final String CHECK_FLIGHTS = "SELECT * FROM FLIGHTS WHERE fid = ?";
    private PreparedStatement checkFlights;

    private static final String CANCEL_RESERVATION = "UPDATE RESERVATIONS SET cancel_status = 1 WHERE rid = ? ";
    private PreparedStatement cancelReservations;

    private static final String UPDATE_BALANCE = "UPDATE USERS SET balance = ? WHERE username = ?";
    private PreparedStatement updateBalance;

    private static final String UPDATE_PAYSTATUS = "UPDATE RESERVATIONS SET pay_status = 1 WHERE rid = ?";
    private PreparedStatement updatePaystatus;

    private static final String CHECK_CAPACITY1 = "SELECT COUNT(*) FROM RESERVATIONS WHERE fid1 = ?";
    private PreparedStatement checkCapacity1;

    private static final String CHECK_CAPACITY2 = "SELECT COUNT(*) FROM RESERVATIONS WHERE fid2 = ?";
    private PreparedStatement checkCapacity2;

    private static final String MAX_RESERVATION_ID = "SELECT ISNULL(MAX(rid), 0) FROM RESERVATIONS";
    private PreparedStatement maxReservationID;

    private boolean loggedIn;

    private String currentUser;

    private List<itinerary> recentSearches = new ArrayList<>();

    private int currentReservationID;

    public Query() throws SQLException, IOException {
        this(null, null, null, null);
    }

    protected Query(String serverURL, String dbName, String adminName, String password)
            throws SQLException, IOException {
        conn = serverURL == null ? openConnectionFromDbConn()
                : openConnectionFromCredential(serverURL, dbName, adminName, password);

        prepareStatements();
    }

    /**
     * Return a connecion by using dbconn.properties file
     *
     * @throws SQLException
     * @throws IOException
     */
    public static Connection openConnectionFromDbConn() throws SQLException, IOException {
        // Connect to the database with the provided connection configuration
        Properties configProps = new Properties();
        configProps.load(new FileInputStream("dbconn.properties"));
        String serverURL = configProps.getProperty("hw5.server_url");
        String dbName = configProps.getProperty("hw5.database_name");
        String adminName = configProps.getProperty("hw5.username");
        String password = configProps.getProperty("hw5.password");
        return openConnectionFromCredential(serverURL, dbName, adminName, password);
    }

    /**
     * Return a connecion by using the provided parameter.
     *
     * @param serverURL example: example.database.widows.net
     * @param dbName    database name
     * @param adminName username to login server
     * @param password  password to login server
     *
     * @throws SQLException
     */
    protected static Connection openConnectionFromCredential(String serverURL, String dbName,
                                                             String adminName, String password) throws SQLException {
        String connectionUrl =
                String.format("jdbc:sqlserver://%s:1433;databaseName=%s;user=%s;password=%s", serverURL,
                        dbName, adminName, password);
        Connection conn = DriverManager.getConnection(connectionUrl);

        // By default, automatically commit after each statement
        conn.setAutoCommit(true);

        // By default, set the transaction isolation level to serializable
        conn.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);

        return conn;
    }

    /**
     * Get underlying connection
     */
    public Connection getConnection() {
        return conn;
    }

    /**
     * Closes the application-to-database connection
     */
    public void closeConnection() throws SQLException {
        conn.close();
    }

    /**
     * Clear the data in any custom tables created.
     *
     * WARNING! Do not drop any tables and do not clear the flights table.
     */
    public void clearTables() {
        try {
            clearUsers.executeUpdate();
            clearReservations.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /*
     * prepare all the SQL statements in this method.
     */
    private void prepareStatements() throws SQLException {
        checkFlightCapacityStatement = conn.prepareStatement(CHECK_FLIGHT_CAPACITY);
        tranCountStatement = conn.prepareStatement(TRANCOUNT_SQL);
        clearUsers = conn.prepareStatement(CLEAR_USERS);
        clearReservations = conn.prepareStatement(CLEAR_RESERVATIONS);
        createAccount = conn.prepareStatement(CREATE_ACCOUNT);
        checkAccount = conn.prepareStatement(CHECK_ACCOUNT);
        directFlights = conn.prepareStatement(DIRECT_FLIGHTS);
        indirectFlights = conn.prepareStatement(INDIRECT_FLIGHTS);
        createReservation = conn.prepareStatement(CREATE_RESERVATION);
        checkReservationByUsername = conn.prepareStatement(CHECK_RESERVATION_BY_USERNAME);
        checkReservationDate = conn.prepareStatement(CHECK_RESERVATION_DATE);
        checkFlights = conn.prepareStatement(CHECK_FLIGHTS);
        cancelReservations = conn.prepareStatement(CANCEL_RESERVATION);
        updateBalance = conn.prepareStatement(UPDATE_BALANCE);
        updatePaystatus = conn.prepareStatement(UPDATE_PAYSTATUS);
        checkCapacity1 = conn.prepareStatement(CHECK_CAPACITY1);
        checkCapacity2 = conn.prepareStatement(CHECK_CAPACITY2);
        maxReservationID = conn.prepareStatement(MAX_RESERVATION_ID);
    }

    /**
     * Takes a user's username and password and attempts to log the user in.
     *
     * @param username user's username
     * @param password user's password
     *
     * @return If someone has already logged in, then return "User already logged in\n" For all other
     *         errors, return "Login failed\n". Otherwise, return "Logged in as [username]\n".
     */
    public String transaction_login(String username, String password) {
        if(loggedIn) {
            return "User already logged in\n";
        }
        try {
            checkAccount.setString(1, username);
            ResultSet result = checkAccount.executeQuery();
            if(result.next()) {
                byte[] salt = result.getBytes(3);
                KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, HASH_STRENGTH, KEY_LENGTH);

                SecretKeyFactory factory = null;
                byte[] hash = null;
                try {
                    factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                    hash = factory.generateSecret(spec).getEncoded();
                } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
                    throw new IllegalStateException();
                }

                if (Arrays.equals(hash, result.getBytes(2))) {
                    loggedIn = true;
                    currentUser = username;
                    return "Logged in as " + username + "\n";
                } else {
                    return "Login failed\n";
                }
            } else {
                return "Login failed\n";
            }
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            checkDanglingTransaction();
        }
        return "Login failed\n";
    }

    /**
     * Implement the create user function.
     *
     * @param username   new user's username. User names are unique the system.
     * @param password   new user's password.
     * @param initAmount initial amount to deposit into the user's account, should be >= 0 (failure
     *                   otherwise).
     *
     * @return either "Created user {@code username}\n" or "Failed to create user\n" if failed.
     */
    public String transaction_createCustomer(String username, String password, int initAmount) {
        if(initAmount < 0) {
            return "Failed to create user\n";
        }

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, HASH_STRENGTH, KEY_LENGTH);

        SecretKeyFactory factory = null;
        byte[] hash = null;
        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            hash = factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new IllegalStateException();
        }

        try {
            checkAccount.setString(1, username);
            ResultSet result = checkAccount.executeQuery();
            if(result.next()) {
                return "Failed to create user\n";
            } else {
                createAccount.clearParameters();
                createAccount.setString(1, username);
                createAccount.setBytes(2, hash);
                createAccount.setBytes(3, salt);
                createAccount.setInt(4, initAmount);
                createAccount.executeUpdate();
                return "Created user " + username + "\n";
            }
        } catch (SQLException e) {
            return "Failed to create user\n";
        } finally {
            checkDanglingTransaction();
        }
    }

    /**
     * Implement the search function.
     *
     * Searches for flights from the given origin city to the given destination city, on the given day
     * of the month. If {@code directFlight} is true, it only searches for direct flights, otherwise
     * is searches for direct flights and flights with two "hops." Only searches for up to the number
     * of itineraries given by {@code numberOfItineraries}.
     *
     * The results are sorted based on total flight time.
     *
     * @param originCity
     * @param destinationCity
     * @param directFlight        if true, then only search for direct flights, otherwise include
     *                            indirect flights as well
     * @param dayOfMonth
     * @param numberOfItineraries number of itineraries to return
     *
     * @return If no itineraries were found, return "No flights match your selection\n". If an error
     *         occurs, then return "Failed to search\n".
     *
     *         Otherwise, the sorted itineraries printed in the following format:
     *
     *         Itinerary [itinerary number]: [number of flights] flight(s), [total flight time]
     *         minutes\n [first flight in itinerary]\n ... [last flight in itinerary]\n
     *
     *         Each flight should be printed using the same format as in the {@code Flight} class.
     *         Itinerary numbers in each search should always start from 0 and increase by 1.
     *
     * @see Flight#toString()
     */
    public String transaction_search(String originCity, String destinationCity, boolean directFlight,
                                     int dayOfMonth, int numberOfItineraries) {
        List<itinerary> itineraryFlights = new ArrayList<>();
        int itineraryNumber = 0;
        int directFlightsCount = 0;
        String output = "";

        try {
            directFlights.setInt(1, numberOfItineraries);
            directFlights.setString(2, originCity);
            directFlights.setString(3, destinationCity);
            directFlights.setInt(4, dayOfMonth);
            ResultSet resultsForDirect = directFlights.executeQuery();
            while(resultsForDirect.next()) {
                Flight f1 = fillFlight1(resultsForDirect);
                Flight f2 = fillFlight1Null();
                itinerary direct = new itinerary();
                direct.f1 = f1;
                direct.f2 = f2;
                itineraryFlights.add(direct);
                directFlightsCount++;
            }
            if(!directFlight) {
                indirectFlights.setInt(1, (numberOfItineraries - directFlightsCount));
                indirectFlights.setString(2, originCity);
                indirectFlights.setString(3, destinationCity);
                indirectFlights.setInt(4, dayOfMonth);
                ResultSet resultsForIndirect = indirectFlights.executeQuery();
                while (resultsForIndirect.next()) {
                    Flight f1 = fillFlight1(resultsForIndirect);
                    Flight f2 = fillFlight2(resultsForIndirect);
                    itinerary indirect = new itinerary();
                    indirect.f1 = f1;
                    indirect.f2 = f2;
                    itineraryFlights.add(indirect);
                }
            }
            itineraryFlights.sort(new itinerary());
            recentSearches = new ArrayList<>(itineraryFlights);
            while(itineraryFlights.size() > 0) {
                itinerary next = itineraryFlights.remove(0);
                if(next.f2.fid == 0) {
                    output += "Itinerary " + itineraryNumber + ": 1 flight(s), " + next.f1.time + " minutes\n"
                            + next.f1.toString() + "\n";
                } else {
                    output += "Itinerary " + itineraryNumber + ": 2 flight(s), " + (next.f1.time + next.f2.time) + " minutes\n"
                            + next.f1.toString() + "\n" + next.f2.toString() + "\n";
                }
                itineraryNumber++;
            }
            if(output.equals("")) {
                return "No flights match your selection\n";
            } else {
                return output;
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return "Failed to search\n";
        } finally {
            checkDanglingTransaction();
        }
    }

    /**
     * Implements the book itinerary function.
     *
     * @param itineraryId ID of the itinerary to book. This must be one that is returned by search in
     *                    the current session.
     *
     * @return If the user is not logged in, then return "Cannot book reservations, not logged in\n".
     *         If the user is trying to book an itinerary with an invalid ID or without having done a
     *         search, then return "No such itinerary {@code itineraryId}\n". If the user already has
     *         a reservation on the same day as the one that they are trying to book now, then return
     *         "You cannot book two flights in the same day\n". For all other errors, return "Booking
     *         failed\n".
     *
     *         And if booking succeeded, return "Booked flight(s), reservation ID: [reservationId]\n"
     *         where reservationId is a unique number in the reservation system that starts from 1 and
     *         increments by 1 each time a successful reservation is made by any user in the system.
     */
    public String transaction_book(int itineraryId) {

        for (int j = 0; j < 3; j++) {
            try {
                conn.setAutoCommit(false);
                if(!loggedIn) {
                    conn.commit();
                    return "Cannot book reservations, not logged in\n";
                }

                if(recentSearches.size() == 0 || recentSearches.size() < itineraryId) {
                    conn.commit();
                    return "No such itinerary " + itineraryId + "\n";
                }

                if (recentSearches.size() >= itineraryId) {
                    itinerary i = recentSearches.get(itineraryId);
                    checkReservationDate.setString(1, currentUser);
                    ResultSet date = checkReservationDate.executeQuery();

                    while (date.next()) {
                        if (date.getInt(1) == i.f1.dayOfMonth) {
                            conn.commit();
                            return "You cannot book two flights in the same day\n";
                        }
                    }
                }


                if (recentSearches.size() >= itineraryId) {
                    itinerary i = recentSearches.get(itineraryId);
                    currentReservationID++;

                    int f1 = i.f1.fid;
                    int f2 = i.f2.fid;

                    checkCapacity1.setInt(1, f1);
                    ResultSet totalReserved = checkCapacity1.executeQuery();
                    totalReserved.next();
                    checkFlights.setInt(1, f1);
                    ResultSet capacity1 = checkFlights.executeQuery();
                    capacity1.next();
                    if(capacity1.getInt("capacity") <= totalReserved.getInt(1)) {
                        conn.commit();
                        return "Booking failed\n";
                    }

                    checkFlights.clearParameters();

                    if(f2 != 0) {
                        checkCapacity2.setInt(1, f2);
                        ResultSet totalReserved2 = checkCapacity2.executeQuery();
                        totalReserved2.next();
                        checkFlights.setInt(1, f2);
                        ResultSet capacity2 = checkFlights.executeQuery();
                        capacity2.next();
                        if(capacity2.getInt("capacity") <= totalReserved2.getInt(1)) {
                            conn.commit();
                            return "Booking failed\n";
                        }
                    }


                    if (f2 == 0) {
                        ResultSet maxes = maxReservationID.executeQuery();
                        maxes.next();
                        int max = maxes.getInt(1);
                        createReservation.setInt(1, max + 1);
                        createReservation.setString(2, currentUser);
                        createReservation.setInt(3, 0);
                        createReservation.setInt(4, f1);
                        createReservation.setNull(5, Types.INTEGER);
                        createReservation.setInt(6, 0);
                        createReservation.executeUpdate();
                        conn.commit();
                        return "Booked flight(s), reservation ID: " + (max + 1) + "\n";
                    } else {
                        ResultSet maxes = maxReservationID.executeQuery();
                        maxes.next();
                        int max = maxes.getInt(1);
                        createReservation.setInt(1, max + 1);
                        createReservation.setString(2, currentUser);
                        createReservation.setInt(3, 0);
                        createReservation.setInt(4, f1);
                        createReservation.setInt(5, f2);
                        createReservation.setInt(6, 0);
                        createReservation.executeUpdate();
                        conn.commit();
                        return "Booked flight(s), reservation ID: " + (max + 1) + "\n";
                    }
                }
            } catch (SQLException e) {
                if(isDeadLock(e)) {
                    try {
                        conn.rollback();
                    } catch (SQLException ex) {
                        ex.printStackTrace();
                    }
                }
                try {
                    conn.commit();
                } catch (SQLException ex) {
                    ex.printStackTrace();
                    return "Booking failed\n";
                }

                e.printStackTrace();
            } finally {
                try {
                    conn.setAutoCommit(true);
                } catch (SQLException e) {
                    e.printStackTrace();
                }
                checkDanglingTransaction();
            }
        }
        return "No such itinerary " + itineraryId + "\n";
    }

    /**
     * Implements the pay function.
     *
     * @param reservationId the reservation to pay for.
     *
     * @return If no user has logged in, then return "Cannot pay, not logged in\n" If the reservation
     *         is not found / not under the logged in user's name, then return "Cannot find unpaid
     *         reservation [reservationId] under user: [username]\n" If the user does not have enough
     *         money in their account, then return "User has only [balance] in account but itinerary
     *         costs [cost]\n" For all other errors, return "Failed to pay for reservation
     *         [reservationId]\n"
     *
     *         If successful, return "Paid reservation: [reservationId] remaining balance:
     *         [balance]\n" where [balance] is the remaining balance in the user's account.
     */
    public String transaction_pay(int reservationId) {
        for(int i = 0; i < 3; i++) {
            try {
                conn.setAutoCommit(false);
                if (!loggedIn) {
                    conn.commit();
                    return "Cannot pay, not logged in\n";
                }
                checkAccount.setString(1, currentUser);
                ResultSet user = checkAccount.executeQuery();
                user.next();

                checkReservationByUsername.setString(1, currentUser);
                ResultSet reservation = checkReservationByUsername.executeQuery();
                while (reservation.next()) {
                    if (reservation.getInt("rid") == reservationId) {
                        if (reservation.getInt("pay_status") == 1) {
                            conn.commit();
                            return "Cannot find unpaid reservation " + reservationId + " under user: " + currentUser + "\n";
                        }

                        int total = 0;
                        int fid1 = reservation.getInt("fid1");
                        int fid2 = reservation.getInt("fid2");

                        checkFlights.setInt(1, fid1);
                        ResultSet price1 = checkFlights.executeQuery();
                        price1.next();
                        int half = price1.getInt("price");
                        total += half;

                        checkFlights.clearParameters();

                        if (fid2 != 0) {
                            checkFlights.setInt(1, fid2);
                            ResultSet price2 = checkFlights.executeQuery();
                            price2.next();
                            int half2 = price2.getInt("price");
                            total += half2;
                        }

                        int balance = user.getInt("balance");

                        if (balance < total) {
                            conn.commit();
                            return "User has only " + balance + " in account but itinerary costs " + total + "\n";
                        } else {
                            int leftOver = balance - total;
                            updateBalance.setInt(1, leftOver);
                            updateBalance.setString(2, currentUser);
                            updateBalance.executeUpdate();
                            updatePaystatus.setInt(1, reservationId);
                            updatePaystatus.executeUpdate();
                            conn.commit();
                            return "Paid reservation: " + reservationId + " remaining balance: " + leftOver + "\n";
                        }
                    }
                }
            } catch (SQLException e) {
                e.printStackTrace();
                if(isDeadLock(e)) {
                    try {
                        conn.rollback();
                    } catch (SQLException ex) {
                        ex.printStackTrace();
                    }
                }
                try {
                    conn.commit();
                } catch (SQLException ex) {
                    ex.printStackTrace();
                    return "Failed to pay for reservation " + reservationId + "\n";
                }
            } finally {
                try {
                    conn.setAutoCommit(true);
                } catch (SQLException e) {
                    e.printStackTrace();
                }
                checkDanglingTransaction();
            }
        }
        return "Cannot find unpaid reservation " + reservationId + " under user: " + currentUser + "\n";
    }

    /**
     * Implements the reservations function.
     *
     * @return If no user has logged in, then return "Cannot view reservations, not logged in\n" If
     *         the user has no reservations, then return "No reservations found\n" For all other
     *         errors, return "Failed to retrieve reservations\n"
     *
     *         Otherwise return the reservations in the following format:
     *
     *         Reservation [reservation ID] paid: [true or false]:\n [flight 1 under the
     *         reservation]\n [flight 2 under the reservation]\n Reservation [reservation ID] paid:
     *         [true or false]:\n [flight 1 under the reservation]\n [flight 2 under the
     *         reservation]\n ...
     *
     *         Each flight should be printed using the same format as in the {@code Flight} class.
     *
     * @see Flight#toString()
     */
    public String transaction_reservations() {
        for(int i = 0; i < 3; i++) {
            try {
                conn.setAutoCommit(false);
                if (!loggedIn) {
                    conn.commit();
                    return "Cannot view reservations, not logged in\n";
                }
                String output = "";
                checkReservationByUsername.setString(1, currentUser);
                ResultSet reservations = checkReservationByUsername.executeQuery();
                while (reservations.next()) {
                    if (reservations.getInt("cancel_status") == 0) {
                        String boolPay = "true";
                        if (reservations.getInt("pay_status") == 0) {
                            boolPay = "false";
                        }
                        int fid1 = reservations.getInt("fid1");
                        int fid2 = reservations.getInt("fid2");

                        output += "Reservation " + reservations.getInt("rid") + " paid: " + boolPay + ":\n";

                        checkFlights.setInt(1, fid1);
                        ResultSet price1 = checkFlights.executeQuery();
                        price1.next();
                        Flight f1 = fillFlight1(price1);

                        output += f1.toString() + "\n";

                        checkFlights.clearParameters();

                        if (fid2 != 0) {
                            checkFlights.setInt(1, fid2);
                            ResultSet price2 = checkFlights.executeQuery();
                            price2.next();
                            Flight f2 = fillFlight1(price2);

                            output += f2.toString() + "\n";
                        }
                    }
                    if (output.equals("")) {
                        conn.commit();
                        return "No reservations found\n";
                    }
                    conn.commit();
                    return output;
                }
            } catch (SQLException e) {
                if (isDeadLock(e)) {
                    try {
                        conn.rollback();
                    } catch (SQLException ex) {
                        ex.printStackTrace();
                    }
                }
                try {
                    conn.commit();
                } catch (SQLException ex) {
                    ex.printStackTrace();
                    return "Failed to retrieve reservations\n";
                }
            } finally {
                try {
                    conn.setAutoCommit(false);
                } catch (SQLException e) {
                    e.printStackTrace();
                }
                checkDanglingTransaction();
            }
        }
        return "No reservations found\n";
    }

    /**
     * Implements the cancel operation.
     *
     * @param reservationId the reservation ID to cancel
     *
     * @return If no user has logged in, then return "Cannot cancel reservations, not logged in\n" For
     *         all other errors, return "Failed to cancel reservation [reservationId]\n"
     *
     *         If successful, return "Canceled reservation [reservationId]\n"
     *
     *         Even though a reservation has been canceled, its ID should not be reused by the system.
     */
    public String transaction_cancel(int reservationId) {
        for (int i = 0; i < 3; i++) {
            try {
                conn.setAutoCommit(false);
                if (!loggedIn) {
                    conn.commit();
                    return "Cannot cancel reservations, not logged in\n";
                }
                checkAccount.setString(1, currentUser);
                ResultSet user = checkAccount.executeQuery();
                user.next();
                checkReservationByUsername.setString(1, currentUser);
                ResultSet reservation = checkReservationByUsername.executeQuery();
                while (reservation.next()) {
                    if (reservation.getInt("cancel_status") == 1) {
                        conn.commit();
                        return "Failed to cancel reservation " + reservationId + "\n";
                    }
                    if (reservation.getInt("rid") == reservationId) {
                        cancelReservations.setInt(1, reservationId);
                        cancelReservations.executeUpdate();
                        if (reservation.getInt("pay_status") == 1) {
                            int total = 0;
                            int fid1 = reservation.getInt("fid1");
                            int fid2 = reservation.getInt("fid2");

                            checkFlights.setInt(1, fid1);
                            ResultSet price1 = checkFlights.executeQuery();
                            price1.next();
                            int half = price1.getInt("price");
                            total += half;

                            checkFlights.clearParameters();

                            if (fid2 != 0) {
                                checkFlights.setInt(1, fid2);
                                ResultSet price2 = checkFlights.executeQuery();
                                price2.next();
                                int half2 = price2.getInt("price");
                                total += half2;
                            }

                            int balance = user.getInt("balance");
                            int newBalance = balance + total;
                            updateBalance.setInt(1, newBalance);
                            updateBalance.setString(2, currentUser);
                            updateBalance.executeUpdate();
                            conn.commit();
                            return "Canceled reservation " + reservationId + "\n";
                        }
                        conn.commit();
                        return "Canceled reservation " + reservationId + "\n";
                    }
                }
            } catch (SQLException e) {
                if(isDeadLock(e)) {
                    try {
                        conn.rollback();
                    } catch (SQLException ex) {
                        ex.printStackTrace();
                    }
                }
                try {
                    conn.commit();
                } catch (SQLException ex) {
                    ex.printStackTrace();
                    return "Failed to cancel reservation " + reservationId + "\n";
                }
            } finally {
                checkDanglingTransaction();
            }
        }
        return "Failed to cancel reservation " + reservationId + "\n";
    }

    /**
     * Example utility function that uses prepared statements
     */
    private int checkFlightCapacity(int fid) throws SQLException {
        checkFlightCapacityStatement.clearParameters();
        checkFlightCapacityStatement.setInt(1, fid);
        ResultSet results = checkFlightCapacityStatement.executeQuery();
        results.next();
        int capacity = results.getInt("capacity");
        results.close();

        return capacity;
    }

    /**
     * Throw IllegalStateException if transaction not completely complete, rollback.
     *
     */
    private void checkDanglingTransaction() {
        try {
            try (ResultSet rs = tranCountStatement.executeQuery()) {
                rs.next();
                int count = rs.getInt("tran_count");
                if (count > 0) {
                    throw new IllegalStateException(
                            "Transaction not fully commit/rollback. Number of transaction in process: " + count);
                }
            } finally {
                conn.setAutoCommit(true);
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Database error", e);
        }
    }

    private static boolean isDeadLock(SQLException ex) {
        return ex.getErrorCode() == 1205;
    }

    /**
     * A class to store flight information.
     */
    class Flight {
        public int fid;
        public int dayOfMonth;
        public String carrierId;
        public String flightNum;
        public String originCity;
        public String destCity;
        public int time;
        public int capacity;
        public int price;


        @Override
        public String toString() {
            return "ID: " + fid + " Day: " + dayOfMonth + " Carrier: " + carrierId + " Number: "
                    + flightNum + " Origin: " + originCity + " Dest: " + destCity + " Duration: " + time
                    + " Capacity: " + capacity + " Price: " + price;
        }
    }

    private Flight fillFlight1(ResultSet result) {
        Flight f = new Flight();
        try {
            f.fid = result.getInt("fid");
            f.dayOfMonth = result.getInt("day_of_month");
            f.carrierId = result.getString("carrier_id");
            f.flightNum = result.getString("flight_num");
            f.originCity = result.getString("origin_city");
            f.destCity = result.getString("dest_city");
            f.time = result.getInt("actual_time");
            f.capacity = result.getInt("capacity");
            f.price = result.getInt("price");
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return f;
    }

    private Flight fillFlight1Null() {
        Flight f = new Flight();
        f.fid = 0;
        f.dayOfMonth = 0;
        f.carrierId = null;
        f.flightNum = null;
        f.originCity = null;
        f.destCity = null;
        f.time = 0;
        f.capacity = 0;
        f.price = 0;
        return f;
    }

    private Flight fillFlight2(ResultSet result) {
        Flight f = new Flight();
        try {
            f.fid = result.getInt("fid2");
            f.dayOfMonth = result.getInt("day_of_month2");
            f.carrierId = result.getString("carrier_id2");
            f.flightNum = result.getString("flight_num2");
            f.originCity = result.getString("origin_city2");
            f.destCity = result.getString("dest_city2");
            f.time = result.getInt("actual_time2");
            f.capacity = result.getInt("capacity2");
            f.price = result.getInt("price2");
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return f;
    }

    private class itinerary implements Comparator<itinerary>{
        Flight f1;
        Flight f2;

        public int compare(itinerary i1, itinerary i2) {
            if((i1.f1.time + i1.f2.time) < (i2.f1.time + i2.f2.time)) {
                return -1;
            } else if ((i1.f1.time + i1.f2.time) > (i2.f1.time + i2.f2.time)) {
                return 1;
            } else {
                if(i1.f1.fid < i2.f1.fid) {
                    return -1;
                } else if(i1.f1.fid > i2.f1.fid) {
                    return 1;
                } else {
                    return Integer.compare(i1.f2.fid, i2.f2.fid);
                }
            }
        }

    }
}

