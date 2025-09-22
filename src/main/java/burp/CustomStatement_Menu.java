/*
 * Custom Statement Menu for HackBar
 * Allows users to create and manage custom SQL statements
 */
package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JSeparator;

/**
 * Custom Statement Menu - 自定义语句菜单
 * @author HackBar Extension
 */
public class CustomStatement_Menu extends JMenu{
    public BurpExtender myburp;
    private static final String CONFIG_FILE = "custom_payloads.ini";
    private List<String> customStatements;
    
    CustomStatement_Menu(BurpExtender burp){
        this.setText("Custom Statements");
        this.myburp = burp;
        this.customStatements = new ArrayList<>();
        
        // 加载自定义语句
        loadCustomStatements();
        
        // 创建菜单
        createMenu();
    }
    
    /**
     * 从配置文件加载自定义语句
     */
    private void loadCustomStatements() {
        try {
            File file = new File(CONFIG_FILE);
            if (file.exists()) {
                try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        line = line.trim();
                        if (!line.isEmpty() && !line.startsWith("#") && !line.startsWith("[")) {
                            // 检查是否包含等号，如果包含则只取等号后面的部分
                            if (line.contains("=")) {
                                String[] parts = line.split("=", 2);
                                if (parts.length == 2) {
                                    String value = parts[1].trim();
                                    if (!value.isEmpty()) {
                                        customStatements.add(value);
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                // 如果文件不存在，创建默认ini文件
                createDefaultIniFile();
                // 然后重新加载
                loadCustomStatements();
            }
        } catch (IOException e) {
            e.printStackTrace();
            // 如果读取失败，创建默认ini文件
            createDefaultIniFile();
        }
    }
    

    
    /**
     * 创建默认的ini文件
     */
    private void createDefaultIniFile() {
        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(CONFIG_FILE));
            writer.write("[SQL Injection Payloads]\n");
            writer.write("# Custom SQL injection statements\n");
            writer.write("payload1=' OR '1'='1\n");
            writer.write("payload2=' UNION SELECT 1,2,3--\n");
            writer.write("payload3='; DROP TABLE users--\n");
            writer.write("payload4=' AND SLEEP(5)--\n");
            writer.write("payload5=' OR 1=1#\n");
            writer.write("payload6=admin'--\n");
            writer.write("payload7=' OR 'x'='x\n");
            writer.write("payload8=') OR ('1'='1\n");
            writer.close();
        } catch (IOException e) {
            System.err.println("Error creating default ini file: " + e.getMessage());
        }
    }
    

    
    /**
     * 创建菜单项
     */
    private void createMenu() {
        // 清空现有菜单项
        this.removeAll();
        
        // 添加管理菜单项
        JMenuItem reloadItem = new JMenuItem("Reload Payloads");
        reloadItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                reloadStatements();
            }
        });
        this.add(reloadItem);
        
        // 添加分隔符
        this.add(new JSeparator());
        
        // 添加自定义语句菜单项
        for (int i = 0; i < customStatements.size(); i++) {
            String statement = customStatements.get(i);
            String displayText = statement.length() > 30 ? 
                statement.substring(0, 30) + "..." : statement;
            
            JMenuItem menuItem = new JMenuItem(displayText);
            menuItem.setActionCommand(statement);
            menuItem.addActionListener(new CustomStatementListener(myburp));
            this.add(menuItem);
        }
    }
    
    /**
     * 重新加载自定义语句
     */
    private void reloadStatements() {
        customStatements.clear();
        loadCustomStatements();
        createMenu();
        JOptionPane.showMessageDialog(this, "Statements reloaded successfully!");
    }
    

}

/**
 * 自定义语句菜单项监听器
 */
class CustomStatementListener implements ActionListener {
    BurpExtender myburp;
    
    CustomStatementListener(BurpExtender burp) {
        myburp = burp;
    }
    
    @Override
    public void actionPerformed(ActionEvent e) {
        try {
            int[] selectedIndex = myburp.context.getSelectionBounds();
            IHttpRequestResponse req = myburp.context.getSelectedMessages()[0];
            byte[] request = req.getRequest();
            byte[] param = new byte[selectedIndex[1] - selectedIndex[0]];
            System.arraycopy(request, selectedIndex[0], param, 0, selectedIndex[1] - selectedIndex[0]);
            String selectString = new String(param);
            String customStatement = e.getActionCommand();
            
            // 应用自定义语句
            byte[] newRequest = applyCustomStatement(request, selectString, customStatement, selectedIndex);
            req.setRequest(newRequest);
            
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(null, 
                "Error applying custom statement: " + ex.getMessage(), 
                "Error", 
                JOptionPane.ERROR_MESSAGE);
        }
    }
    
    /**
     * 应用自定义语句到请求中
     */
    private byte[] applyCustomStatement(byte[] request, String selectedString, String customStatement, int[] selectedIndex) {
        // 使用Methods类的do_modify_request方法来修改请求
        return Methods.do_modify_request(request, selectedIndex, customStatement);
    }
}