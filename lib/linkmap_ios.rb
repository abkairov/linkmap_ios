require "linkmap_ios/version"
require "filesize"
require "json"

module LinkmapIos
  Library = Struct.new(:name, :group, :size, :objects, :dead_symbol_size, :filtered_symbol_size, :pod)

  class LinkmapParser
    attr_reader :id_map
    attr_reader :library_map

    def initialize(file_path, filter_str)
      @file_path = file_path
      @filter_re = nil
      if !filter_str.nil?
        a = filter_str.split(",")
        @filter_re = a.map { |s| {:re => (Regexp.new s), :str => s, :size => 0 } }
      end
      @id_map = {}
      @library_map = {}
      @section_map = {}
      @groups_map = {}
      if !@filter_re.nil?
        for f in @filter_re
          @groups_map[f[:str]] = 0
          puts "Grouping by: #{f[:str]} = #{f[:re].to_s}"
        end
        # @groups_map.each { |k,v| puts "Groups Map: #{k} = #{v.to_s}" }
      end
    end

    def hash
      # Cache
      return @result_hash if @result_hash

      parse

      total_size = @library_map.values.map(&:size).inject(:+)
      @groups_map.each { |k,v| puts "Groups Map: #{k} = #{v.to_s}" }
      grouped_sizes = @groups_map.map { |k, s| {:group => k, :size => s }}
      #grouped_sizes = @library_map.values.map(&:filtered_symbol_size).inject(:+)
      detail = @library_map.values.map { |lib| {:library => lib.name, :pod => lib.pod, :size => lib.size, :dead_symbol_size => lib.dead_symbol_size, :objects => lib.objects.map { |o| @id_map[o][:object] }}}
      total_dead_size = @library_map.values.map(&:dead_symbol_size).inject(:+)

      # puts total_size
      # puts detail

      @result_hash = {:total => total_size, :detail => detail, :total_dead => total_dead_size, :total_grouped => grouped_sizes}
      @result_hash
    end

    def json
      JSON.pretty_generate(hash)
    end

    def report
      result = hash

      report = "# Total size\n"
      report << "#{Filesize.from(result[:total].to_s + 'B').pretty}\n"
      report << "# Dead Size\n"
      report << "#{Filesize.from(result[:total_dead].to_s + 'B').pretty}\n"
      if !@filter_re.nil?
        report << "# Filtered/Grouped Sizes\n"
        for s in result[:total_grouped]
          report << "Group " << s[:group] << ": " << "#{Filesize.from(s[:size].to_s + 'B').pretty}\n"
        end
      end

      report << "\n# Library detail\n"
      result[:detail].sort_by { |h| h[:size] }.reverse.each do |lib|
        report << "#{lib[:library]}   #{Filesize.from(lib[:size].to_s + 'B').pretty}\n"
      end

      sorted_id_map = @id_map.sort_by {|k,v| v[:size] || 0 }.reverse.to_h

      if !@filter_re.nil?
        report << "\n# Object detail per Group\n"
        for s in result[:total_grouped]
          report << "\nGroup " << s[:group] << ": " << "#{Filesize.from(s[:size].to_s + 'B').pretty}\n"
          puts "\nGroup #{s[:group]}: #{Filesize.from(s[:size].to_s + 'B').pretty} "

          i = 0
          sorted_id_map.each_value do |id_info|
            if id_info[:size] && id_info[:group] == s[:group]
              i = i+1
              report << "#{id_info[:group]}/#{id_info[:library]} #{id_info[:object]}: size #{id_info[:size]}\n"
              if i < 7
                puts "Top #{i} #{id_info[:group]}/#{id_info[:library]} #{id_info[:object]}: size #{id_info[:size]}"
              end
            end
          end

        end
      end

      report << "\n\n\n# All Object detail\n"


      #top individual contributors
      puts "\n# All Object detail Top"
      i = 0
      sorted_id_map.each_value do |id_info|
        if id_info[:size]
          i = i+1
          puts "Top #{i} #{id_info[:group]}/#{id_info[:library]} #{id_info[:object]}: size #{id_info[:size]}"
          if i > 7
            break
          end
        end
      end

      #@id_map.sort_by(&:size)
      #@id_map.each_value do |id_info|
      sorted_id_map.each_value do |id_info|
        report << "#{id_info[:group]}/#{id_info[:library]} #{id_info[:object]}   #{Filesize.from(id_info[:size].to_s + 'B').pretty}\n"
      end

      report << "# Uncounted Section Detail"
      @section_map.select do |_, value|
        value[:residual_size] != 0
      end
      .each do |seg_sec_name, value|
        report << "\n#{seg_sec_name}, start_address: #{value[:start_address]}, end_address: #{value[:end_address]}, residual_size: #{value[:residual_size]}"
      end
      report
    end

    private

    def parse
      File.foreach(@file_path).with_index do |line, line_num|
        begin
          # Deal with string like 
          unless line.valid_encoding?
            line = line.encode("UTF-16", :invalid => :replace, :replace => "?").encode('UTF-8')
          end

          if line.start_with? "#"
            if line.start_with? "# Object files:"
              @subparser = :parse_object_files
            elsif line.start_with? "# Sections:"
              @subparser = :parse_sections
            elsif line.start_with? "# Symbols:"
              @subparser = :parse_symbols
            elsif line.start_with? '# Dead Stripped Symbols:'
              @subparser = :parse_dead
            end
          else
            send(@subparser, line)
          end
        rescue => e
          puts "Exception on Link map file line #{line_num}. Content is"
          puts line
          raise e
        end
      end
      puts "There are #{@section_map.values.map{|value| value[:residual_size]}.inject(:+)} Byte in some section can not be analyze"
    end

    def parse_object_files(text)
      groupStr = nil
      isFiltered = false
      if !@filter_re.nil?
        isFiltered = true
        for f in @filter_re
          if text =~ f[:re]
            groupStr = f[:str]
            isFiltered = false
            break
          end
        end
      end

      if text =~ /\[(.*)\].*\/(.*)\((.*)\)/
        idStr = $1
        libStr = isFiltered ? 'FilteredLib' : $2
        groupStr = isFiltered ? 'All_Other_Libs' : groupStr
        objStr = $3
        # Sample:
        # [  6] SomePath/Release-iphoneos/ReactiveCocoa/libReactiveCocoa.a(MKAnnotationView+RACSignalSupport.o)
        # So $1 is id. $2 is library
        id = idStr.to_i
        @id_map[id] = {:library => libStr, :object => objStr, :filtered => isFiltered, :group => groupStr}

        library = (@library_map[libStr] or Library.new(libStr, groupStr, 0, [], 0, 0))
        library.objects << id
        if text.include?('/Pods/')
          # Sample:
          # 0x108BE58D5 0x000000AD [7167] literal string: /var/folders/80/d5nlb_0d05n7bq58h2fy181h0000gp/T/d20180412-62284-c4qbkv/sandbox.SAKPodSharper-React-0.54.3.2@20180412210546/Pods/React/ReactCommon/jschelpers/JSCHelpers.cpp
          # podname is word after "/Pods/", example:React
          divstr = text.split('/Pods/').last
          podname = divstr.split('/').first
          library.pod = podname
        else
          library.pod = ''
        end
        @library_map[libStr] = library
      elsif text =~ /\[(.*)\].*\/(.*)/
        # Sample:
        # System
        # [100] /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS9.3.sdk/System/Library/Frameworks//UIKit.framework/UIKit.tbd
        # Main
        # [  3] /SomePath/Release-iphoneos/CrashDemo.build/Objects-normal/arm64/AppDelegate.o
        # Dynamic Framework
        # [9742] /SomePath/Pods/AFNetworking/Classes/AFNetworking.framework/AFNetworking
        libStr = isFiltered ? 'FilteredFwk' : $2
        groupStr = isFiltered ? 'All_Other_Fwk' : groupStr
        id = $1.to_i
        if text.include?('.framework') and not libStr.include?('.')
          lib = libStr
        else
          if text.end_with?('.a')
            lib = libStr
          else
            lib = libStr.end_with?('.tbd') ? 'System' : 'Main'
          end
        end
        @id_map[id] = {:library => lib, :object => libStr, :filtered => isFiltered, :group => groupStr}

        library = (@library_map[lib] or Library.new(lib, groupStr, 0, [], 0, 0, ''))
        library.objects << id
        @library_map[lib] = library
      elsif text =~ /\[(.*)\]\s*([\w\s]+)/
        # Sample:
        # [  0] linker synthesized
        # [  1] dtrace
        groupStr = isFiltered ? 'All_Main' : groupStr
        id = $1.to_i
        @id_map[id] = {library: 'Main', object: $2, :filtered => isFiltered, :group => groupStr}
      end
    end

    def parse_sections(text)
      # Sample:
      # 0x100005F00 0x031B6A98  __TEXT  __tex
      text_array = text.split(' ').each(&:strip)
      section_name = text_array[3]
      segment_name = text_array[2]
      start_address = text_array.first.to_i(16)
      end_address = start_address + text_array[1].to_i(16)
      # section name may be dulicate in different segment
      seg_sec_name = "#{segment_name}#{section_name}"
      @section_map[seg_sec_name.to_sym] = {
          segment_name: segment_name,
          section_name: section_name,
          start_address: start_address,
          end_address: end_address,
          symbol_size: 0,
          residual_size: text_array[1].to_i(16)
      }
    end

    def parse_symbols(text)
      # Sample
      # 0x1000055C8	0x0000003C	[  4] -[FirstViewController viewWillAppear:]
      if text =~ /^0[xX](.+?)\s+0[xX](.+?)\s+\[(.+?)\]/
        symbol_address = $1.to_i(16)
        symbol_size = $2.to_i(16)
        symbol_file_id = $3.to_i
        id_info = @id_map[symbol_file_id]
        #symbol_name = $'
        #if text.include? 'PacedSender'
        #  puts "Found this line:\n#{text.inspect}"
        #end
        if id_info
          if @library_map[id_info[:library]]
            id_info[:size] = (id_info[:size] or 0) + symbol_size
            @library_map[id_info[:library]].size += symbol_size
            if @library_map[id_info[:library]].group
              @groups_map[id_info[:group]] = (@groups_map[id_info[:group]] or 0) + symbol_size
            end
            # if id_info[:filtered]
            #   @library_map[id_info[:library]].filtered_symbol_size += symbol_size
            # end
            seg_sec_name = @section_map.detect {|seg_sec_name, value| (value[:start_address]...value[:end_address]).include? symbol_address}[0]
            @section_map[seg_sec_name.to_sym][:symbol_size] += symbol_size
            @section_map[seg_sec_name.to_sym][:residual_size] -= symbol_size
          end
        else
          puts "#{text.inspect} can not found object file"
        end
      else
        puts "#{text.inspect} can not match symbol regular"
      end
    end

    def parse_dead(text)
      # <<dead>>  0x00000008  [  3] literal string: v16@0:8
      if text =~ /^<<dead>>\s+0[xX](.+?)\s+\[(.+?)\]\w*/
        id_info = @id_map[$2.to_i]
        if id_info
          id_info[:dead_symbol_size] = (id_info[:dead_symbol_size] or 0) + $1.to_i(16)
          @library_map[id_info[:library]].dead_symbol_size += $1.to_i(16)
        end
      end
    end

  end
end
